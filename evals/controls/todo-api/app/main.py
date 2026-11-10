from typing import Optional

from fastapi import FastAPI, HTTPException, Response
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator


class TodoIn(BaseModel):
    title: str
    completed: bool = False

    @field_validator("title")
    @classmethod
    def validate_title(cls, value):
        value = value.strip()
        if not 1 <= len(value) <= 200:
            raise ValueError("title length must be between 1 and 200 characters")
        return value


class TodoPatch(BaseModel):
    title: Optional[str] = None
    completed: Optional[bool] = None

    @field_validator("title")
    @classmethod
    def validate_title(cls, value):
        if value is None:
            return value
        value = value.strip()
        if not 1 <= len(value) <= 200:
            raise ValueError("title length must be between 1 and 200 characters")
        return value


class TodoOut(BaseModel):
    id: int
    title: str
    completed: bool


app = FastAPI()
todos: dict[int, TodoOut] = {}
next_id = 1


@app.exception_handler(RequestValidationError)
async def handle_validation_error(request, exc):
    if any(error.get("input") is None for error in exc.errors()):
        return JSONResponse(status_code=400, content={"detail": "Explicit null is not allowed"})
    return await request_validation_exception_handler(request, exc)


def find_todo(todo_id):
    if todo_id not in todos:
        raise HTTPException(status_code=404, detail="Todo not found")
    return todos[todo_id]


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/todos", response_model=list[TodoOut])
def list_todos():
    return list(todos.values())


@app.post("/todos", response_model=TodoOut, status_code=201)
def create_todo(payload: TodoIn):
    global next_id
    todo = TodoOut(id=next_id, title=payload.title, completed=payload.completed)
    todos[next_id] = todo
    next_id += 1
    return todo


@app.get("/todos/{todo_id}", response_model=TodoOut)
def get_todo(todo_id: int):
    return find_todo(todo_id)


@app.patch("/todos/{todo_id}", response_model=TodoOut)
def patch_todo(todo_id: int, payload: TodoPatch):
    todo = find_todo(todo_id)
    if not payload.model_fields_set:
        raise HTTPException(status_code=400, detail="PATCH must contain a field")
    if any(getattr(payload, field) is None for field in payload.model_fields_set):
        raise HTTPException(status_code=400, detail="Explicit null is not allowed")
    if "title" in payload.model_fields_set:
        todo.title = payload.title
    if "completed" in payload.model_fields_set:
        todo.completed = payload.completed
    return todo


@app.delete("/todos/{todo_id}", status_code=204)
def delete_todo(todo_id: int):
    find_todo(todo_id)
    del todos[todo_id]
    return Response(status_code=204)
