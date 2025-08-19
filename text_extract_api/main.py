import os
import pathlib
import sys
import time
from typing import Optional

import ollama
import redis
from celery.result import AsyncResult
from fastapi import FastAPI, Form, UploadFile, File, HTTPException
from pydantic import BaseModel, Field, field_validator

from text_extract_api.celery_app import app as celery_app
from text_extract_api.extract.strategies.strategy import Strategy
from text_extract_api.extract.tasks import ocr_task
from text_extract_api.files.file_formats.file_format import FileFormat, FileField
from text_extract_api.files.storage_manager import StorageManager

# Define base path as text_extract_api - required for keeping absolute namespaces
sys.path.insert(0, str(pathlib.Path(__file__).parent.resolve()))

def storage_profile_exists(profile_name: str) -> bool:
    profile_path = os.path.abspath(
        os.path.join(os.getenv('STORAGE_PROFILE_PATH', './storage_profiles'), f'{profile_name}.yaml'))
    if not os.path.isfile(profile_path) and profile_path.startswith('..'):
        # backward compability for ../storage_manager in .env
        sub_profile_path = os.path.normpath(os.path.join('.', profile_path))
        return os.path.isfile(sub_profile_path)
    return True

app = FastAPI()
# Novo endpoint: /ocr/structure
@app.post("/ocr/structure")
async def ocr_structure_endpoint(
    file: UploadFile = File(...),
    prompt: str = Form(...),
    products_api_url: str = Form(...),
    ocr_strategy: str = Form('easyocr'),
    language: str = Form('pt'),
    model: str = Form('llama3.1')
):
    """
    Extrai texto da imagem, consulta produtos via API externa e estrutura os dados com Ollama.
    """
    import tempfile
    import requests
    # 1. Extrair texto via OCR
    from text_extract_api.extract.strategies import easyocr, minicpm_v
    from text_extract_api.files.file_formats.image import ImageFileFormat
    # Salvar imagem temporária
    with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as temp_file:
        temp_file.write(await file.read())
        temp_filename = temp_file.name

    # Criar FileFormat para OCR
    image_format = ImageFileFormat.from_file(temp_filename)
    if ocr_strategy == 'easyocr':
        ocr_strategy_obj = easyocr.EasyOCRStrategy({})
    elif ocr_strategy == 'minicpm_v':
        ocr_strategy_obj = minicpm_v.MiniCPMVStrategy({})
    else:
        os.remove(temp_filename)
        raise HTTPException(status_code=400, detail="Estratégia de OCR não suportada")

    extract_result = ocr_strategy_obj.extract_text(image_format, language=language)
    extracted_text = extract_result.text

    # 2. Consultar produtos via API externa
    try:
        response = requests.get(products_api_url)
        response.raise_for_status()
        produtos = response.json()
    except Exception as e:
        os.remove(temp_filename)
        raise HTTPException(status_code=500, detail=f"Erro ao consultar produtos: {str(e)}")

    # 3. Montar prompt para o Ollama
    ollama_prompt = f"""
{prompt}

Texto extraído:
{extracted_text}

Produtos já cadastrados:
{produtos}
"""

    # 4. Chamar Ollama para estruturar os dados
    import ollama
    ollama_host = os.environ.get("OLLAMA_HOST", "http://ollama:11434")
    client = ollama.Client(host=ollama_host)
    try:
        response = client.generate(model, ollama_prompt)
        structured_data = response.get("response", "")
    except Exception as e:
        os.remove(temp_filename)
        raise HTTPException(status_code=500, detail=f"Erro ao estruturar dados com Ollama: {str(e)}")

    # 5. Limpar arquivo temporário
    os.remove(temp_filename)

    return {"structured_data": structured_data, "raw_text": extracted_text, "produtos": produtos}
# Connect to Redis
redis_url = os.getenv('REDIS_CACHE_URL', 'redis://redis:6379/1')
redis_client = redis.StrictRedis.from_url(redis_url)

@app.post("/ocr")
async def ocr_endpoint(
        strategy: str = Form(...),
        prompt: str = Form(None),
        model: str = Form(...),
        file: UploadFile = File(...),
        ocr_cache: bool = Form(...),
        storage_profile: str = Form('default'),
        storage_filename: str = Form(None),
        language: str = Form('en')
):
    """
    Endpoint to extract text from an uploaded PDF, Image or Office file using different OCR strategies.
    Supports both synchronous and asynchronous processing.
    """
    # Validate input
    try:
        OcrFormRequest(strategy=strategy, prompt=prompt, model=model, ocr_cache=ocr_cache,
                       storage_profile=storage_profile, storage_filename=storage_filename, language=language)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    filename = storage_filename if storage_filename else file.filename
    file_binary = await file.read()
    file_format = FileFormat.from_binary(file_binary, filename, file.content_type)

    print(
        f"Processing Document {file_format.filename} with strategy: {strategy}, ocr_cache: {ocr_cache}, model: {model}, storage_profile: {storage_profile}, storage_filename: {storage_filename}, language: {language}, will be saved as: {filename}")

    # Asynchronous processing using Celery
    task = ocr_task.apply_async(
        args=[file_format.binary, strategy, file_format.filename, file_format.hash, ocr_cache, prompt, model, language,
              storage_profile,
              storage_filename])
    return {"task_id": task.id}


# this is an alias for /ocr - to keep the backward compatibility
@app.post("/ocr/upload")
async def ocr_upload_endpoint(
        strategy: str = Form(...),
        prompt: str = Form(None),
        model: str = Form(None),
        file: UploadFile = File(...),
        ocr_cache: bool = Form(...),
        storage_profile: str = Form('default'),
        storage_filename: str = Form(None),
        language: str = Form('en')
):
    """
    Alias endpoint to extract text from an uploaded PDF/Office/Image file using different OCR strategies.
    Supports both synchronous and asynchronous processing.
    """
    return await ocr_endpoint(strategy, prompt, model, file, ocr_cache, storage_profile, storage_filename, language)


class OllamaGenerateRequest(BaseModel):
    model: str
    prompt: str


class OllamaPullRequest(BaseModel):
    model: str


class OcrRequest(BaseModel):
    strategy: str = Field(..., description="OCR strategy to use")
    prompt: Optional[str] = Field(None, description="Prompt for the Ollama model")
    model: Optional[str] = Field(None, description="Model to use for the Ollama endpoint")
    file: FileField = Field(..., description="Base64 encoded document file")
    ocr_cache: bool = Field(..., description="Enable OCR result caching")
    storage_profile: Optional[str] = Field('default', description="Storage profile to use")
    storage_filename: Optional[str] = Field(None, description="Storage filename to use")
    language: Optional[str] = Field('en', description="Language to use for OCR")

    @field_validator('strategy')
    def validate_strategy(cls, v):
        Strategy.get_strategy(v)
        return v

    @field_validator('storage_profile')
    def validate_storage_profile(cls, v):
        if not storage_profile_exists(v):
            raise ValueError(f"Storage profile '{v}' does not exist.")
        return v


class OcrFormRequest(BaseModel):
    strategy: str = Field(..., description="OCR strategy to use")
    prompt: Optional[str] = Field(None, description="Prompt for the Ollama model")
    model: Optional[str] = Field(None, description="Model to use for the Ollama endpoint")
    ocr_cache: bool = Field(..., description="Enable OCR result caching")
    storage_profile: Optional[str] = Field('default', description="Storage profile to use")
    storage_filename: Optional[str] = Field(None, description="Storage filename to use")
    language: Optional[str] = Field('en', description="Language to use for OCR")

    @field_validator('strategy')
    def validate_strategy(cls, v):
        Strategy.get_strategy(v)
        return v

    @field_validator('storage_profile')
    def validate_storage_profile(cls, v):
        if not storage_profile_exists(v):
            raise ValueError(f"Storage profile '{v}' does not exist.")
        return v


@app.post("/ocr/request")
async def ocr_request_endpoint(request: OcrRequest):
    """
    Endpoint to extract text from an uploaded PDF/Office/Image file using different OCR strategies.
    Supports both synchronous and asynchronous processing.
    """
    # Validate input
    request_data = request.model_dump()
    try:
        OcrRequest(**request_data)
        file = FileFormat.from_base64(request.file, request.storage_filename)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    print(
        f"Processing {file.mime_type} with strategy: {request.strategy}, ocr_cache: {request.ocr_cache}, model: {request.model}, storage_profile: {request.storage_profile}, storage_filename: {request.storage_filename}, language: {request.language}")

    # Asynchronous processing using Celery
    task = ocr_task.apply_async(
        args=[file.binary, request.strategy, file.filename, file.hash, request.ocr_cache, request.prompt,
              request.model, request.language, request.storage_profile, request.storage_filename])
    return {"task_id": task.id}


@app.get("/ocr/result/{task_id}")
async def ocr_status(task_id: str):
    """
    Endpoint to get the status of an OCR task using task_id.
    """
    task = AsyncResult(task_id, app=celery_app)

    if task.state == 'PENDING':
        return {"state": task.state, "status": "Task is pending..."}
    elif task.state == 'PROGRESS':
        task_info = task.info
        if task_info.get('start_time'):
            task_info['elapsed_time'] = time.time() - int(task_info.get('start_time'))
        return {"state": task.state, "status": task.info.get("status"), "info": task_info}
    elif task.state == 'SUCCESS':
        return {"state": task.state, "status": "Task completed successfully.", "result": task.result}
    else:
        return {"state": task.state, "status": str(task.info)}


@app.post("/ocr/clear_cache")
async def clear_ocr_cache():
    """
    Endpoint to clear the OCR result cache in Redis.
    """
    redis_client.flushdb()
    return {"status": "OCR cache cleared"}


@app.get("/storage/list")
async def list_files(storage_profile: str = 'default'):
    """
    Endpoint to list files using the selected storage profile.
    """
    storage_manager = StorageManager(storage_profile)
    files = storage_manager.list()
    return {"files": files}


@app.get("/storage/load")
async def load_file(file_name: str, storage_profile: str = 'default'):
    """
    Endpoint to load a file using the selected storage profile.
    """
    storage_manager = StorageManager(storage_profile)
    content = storage_manager.load(file_name)
    return {"content": content}


@app.delete("/storage/delete")
async def delete_file(file_name: str, storage_profile: str = 'default'):
    """
    Endpoint to delete a file using the selected storage profile.
    """
    storage_manager = StorageManager(storage_profile)
    storage_manager.delete(file_name)
    return {"status": f"File {file_name} deleted successfully"}


@app.post("/llm/pull")
async def pull_llama(request: OllamaPullRequest):
    """
    Endpoint to pull the latest Llama model from the Ollama API.
    """
    print("Pulling " + request.model)
    try:
        response = ollama.pull(request.model)
    except ollama.ResponseError as e:
        print('Error:', e.error)
        raise HTTPException(status_code=500, detail="Failed to pull Llama model from Ollama API")

    return {"status": response.get("status", "Model pulled successfully")}


@app.post("/llm/generate")
async def generate_llama(request: OllamaGenerateRequest):
    """
    Endpoint to generate text using Llama 3.1 model (and other models) via the Ollama API.
    """
    print(request)
    if not request.prompt:
        raise HTTPException(status_code=400, detail="No prompt provided")

    try:
        response = ollama.generate(request.model, request.prompt)
    except ollama.ResponseError as e:
        print('Error:', e.error)
        if e.status_code == 404:
            print("Error: ", e.error)
            ollama.pull(request.model)

        raise HTTPException(status_code=500, detail="Failed to generate text with Ollama API")

    generated_text = response.get("response", "")
    return {"generated_text": generated_text}
