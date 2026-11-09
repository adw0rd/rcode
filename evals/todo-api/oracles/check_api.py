import json
import os
import signal
import subprocess
import sys
import time

import httpx


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def wait_until_healthy(process):
    deadline = time.monotonic() + 10
    with httpx.Client(base_url="http://127.0.0.1:18181", timeout=0.25) as client:
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("uvicorn exited before becoming healthy")
            try:
                remaining = max(0.001, deadline - time.monotonic())
                response = client.get("/health", timeout=min(0.25, remaining))
                if response.status_code == 200 and response.json() == {"status": "ok"}:
                    return
            except (httpx.HTTPError, ValueError):
                pass
            time.sleep(min(0.05, max(0, deadline - time.monotonic())))
    raise RuntimeError("uvicorn did not become healthy within 10 seconds")


def stop_process_group(process):
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


process = subprocess.Popen(
    [
        sys.executable,
        "-m",
        "uvicorn",
        "app.main:app",
        "--host",
        "127.0.0.1",
        "--port",
        "18181",
    ],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    start_new_session=True,
)
try:
    wait_until_healthy(process)
    with httpx.Client(base_url="http://127.0.0.1:18181", timeout=10) as client:
        response = client.get("/health")
        check(response.status_code == 200, "GET /health must return 200")
        check(response.json() == {"status": "ok"}, "GET /health returned an unexpected body")

        response = client.get("/todos")
        check(response.status_code == 200, "Initial GET /todos must return 200")
        check(response.json() == [], "Initial GET /todos must return an empty list")

        response = client.post("/todos", json={"title": "  Первое  "})
        check(response.status_code == 201, "Creating the first todo must return 201")
        first = response.json()
        check(
            first == {"id": 1, "title": "Первое", "completed": False},
            "Creating the first todo returned an unexpected body",
        )

        second = {"id": 2, "title": "Второе", "completed": True}
        response = client.post("/todos", json={"title": "Второе", "completed": True})
        check(response.status_code == 201, "Creating the second todo must return 201")
        check(response.json()["id"] == 2, "Creating the second todo must return id 2")

        response = client.get("/todos")
        check(response.status_code == 200, "GET /todos after creation must return 200")
        check(response.json() == [first, second], "GET /todos after creation returned an unexpected list")

        response = client.get("/todos/1")
        check(response.status_code == 200, "GET /todos/1 after creation must return 200")
        check(response.json() == first, "GET /todos/1 after creation returned an unexpected body")

        response = client.patch("/todos/1", json={"title": " Обновлено ", "completed": True})
        check(response.status_code == 200, "PATCH /todos/1 must return 200")
        updated_first = {"id": 1, "title": "Обновлено", "completed": True}
        check(response.json() == updated_first, "PATCH /todos/1 returned an unexpected body")

        response = client.get("/todos/1")
        check(response.status_code == 200, "GET /todos/1 after PATCH must return 200")
        check(response.json() == updated_first, "PATCH changes were not persisted")

        response = client.patch("/todos/1", json={})
        check(response.status_code == 400, "Empty PATCH /todos/1 must return 400")
        response = client.get("/todos/1")
        check(response.json() == updated_first, "Empty PATCH changed the todo")

        response = client.post("/todos", json={"title": ""})
        check(response.status_code == 422, "Empty title must return 422")

        response = client.post("/todos", json={"title": "   "})
        check(response.status_code == 422, "Whitespace-only title must return 422")

        response = client.post("/todos", json={"title": "x" * 201})
        check(response.status_code == 422, "Title longer than 200 characters must return 422")

        for field in ("title", "completed"):
            response = client.post("/todos", json={"title": "Invalid", field: None})
            check(response.status_code == 400, f"POST with explicit null {field} must return 400")

        response = client.get("/todos")
        check(response.status_code == 200, "GET /todos after invalid writes must return 200")
        check(
            response.json() == [updated_first, second],
            "Invalid writes changed the todo list",
        )

        response = client.get("/todos/999")
        check(response.status_code == 404, "GET /todos/999 must return 404")
        check(response.json() == {"detail": "Todo not found"}, "GET /todos/999 returned an unexpected body")

        response = client.patch("/todos/999", json={"completed": True})
        check(response.status_code == 404, "PATCH /todos/999 must return 404")
        check(response.json() == {"detail": "Todo not found"}, "PATCH /todos/999 returned an unexpected body")

        response = client.delete("/todos/1")
        check(response.status_code == 204, "DELETE /todos/1 must return 204")
        check(response.content == b"", "DELETE /todos/1 must return an empty body")

        response = client.get("/todos/1")
        check(response.status_code == 404, "GET /todos/1 after deletion must return 404")
        check(
            response.json() == {"detail": "Todo not found"},
            "GET /todos/1 after deletion returned an unexpected body",
        )

        response = client.get("/todos")
        check(response.status_code == 200, "GET /todos after deletion must return 200")
        check(response.json() == [second], "DELETE /todos/1 left an unexpected todo list")

        response = client.delete("/todos/1")
        check(response.status_code == 404, "Repeated DELETE /todos/1 must return 404")
        check(
            response.json() == {"detail": "Todo not found"},
            "Repeated DELETE /todos/1 returned an unexpected body",
        )

        response = client.get("/todos")
        check(response.status_code == 200, "GET /todos after repeated deletion must return 200")
        check(response.json() == [second], "Repeated failed DELETE changed the todo list")

        response = client.patch("/todos/999", json={})
        check(response.status_code == 404, "Empty PATCH /todos/999 must return 404")
        check(
            response.json() == {"detail": "Todo not found"},
            "Empty PATCH /todos/999 returned an unexpected body",
        )

        response = client.patch("/todos/2", json={"completed": False})
        check(response.status_code == 200, "PATCH completed from true to false must return 200")
        updated_second = {"id": 2, "title": "Второе", "completed": False}
        check(response.json() == updated_second, "PATCH completed from true to false returned an unexpected body")

        response = client.get("/todos/2")
        check(response.status_code == 200, "GET /todos/2 after disabling completion must return 200")
        check(response.json() == updated_second, "completed=false was not persisted")

        for field in ("title", "completed"):
            response = client.patch("/todos/2", json={field: None})
            check(
                response.status_code in (400, 422),
                f"PATCH with explicit null {field} must be rejected",
            )
            response = client.get("/todos/2")
            check(response.json() == updated_second, f"Null {field} changed the todo")

        response = client.patch("/todos/2", json={"title": ""})
        check(response.status_code == 422, "PATCH with empty title must return 422")
        response = client.get("/todos/2")
        check(response.json() == updated_second, "Empty-title PATCH changed the todo")

        response = client.patch("/todos/2", json={"title": "   "})
        check(response.status_code == 422, "PATCH with whitespace-only title must return 422")
        response = client.get("/todos/2")
        check(response.json() == updated_second, "Invalid PATCH changed the todo")

        response = client.patch("/todos/2", json={"title": "x" * 201})
        check(response.status_code == 422, "PATCH with title longer than 200 characters must return 422")
        response = client.get("/todos/2")
        check(response.json() == updated_second, "Long-title PATCH changed the todo")

        response = client.post("/todos", json={"title": " " + "x" * 200 + " "})
        check(response.status_code == 201, "A 200-character title with surrounding whitespace must be accepted")
        third = {"id": 3, "title": "x" * 200, "completed": False}
        check(response.json() == third, "Creating after deletion must use id 3 and trim before length validation")

        response = client.post("/todos", json={"title": "   "})
        check(response.status_code == 422, "Invalid create before id sequence check must return 422")

        response = client.post("/todos", json={"title": "Четвёртое"})
        check(response.status_code == 201, "Creating the fourth todo must return 201")
        fourth = {"id": 4, "title": "Четвёртое", "completed": False}
        check(response.json() == fourth, "Invalid create consumed an id or changed the next id")

        response = client.get("/todos")
        check(response.status_code == 200, "Final GET /todos must return 200")
        check(response.json() == [updated_second, third, fourth], "Final todo list is inconsistent")

        for todo_id in (2, 3, 4):
            response = client.delete(f"/todos/{todo_id}")
            check(response.status_code == 204, f"Cleanup DELETE /todos/{todo_id} must return 204")
            check(response.content == b"", f"Cleanup DELETE /todos/{todo_id} must return an empty body")
        response = client.get("/todos")
        check(response.status_code == 200, "GET /todos after cleanup must return 200")
        check(response.json() == [], "Cleanup must leave an empty todo list")

    print(json.dumps({"status": "ok"}, separators=(",", ":")))
finally:
    stop_process_group(process)
