import pytest
from fastapi.testclient import TestClient

import app.main as main


@pytest.fixture(autouse=True)
def client():
    main.todos.clear()
    main.next_id = 1
    with TestClient(main.app) as test_client:
        yield test_client
    main.todos.clear()
    main.next_id = 1


def create(client, title="Первое", **fields):
    response = client.post("/todos", json={"title": title, **fields})
    assert response.status_code == 201
    return response.json()


def test_health_and_empty_list(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert client.get("/todos").json() == []


def test_create_trims_title_and_defaults_to_incomplete(client):
    assert create(client, "  Первое  ") == {"id": 1, "title": "Первое", "completed": False}


def test_get_and_list_return_created_todos(client):
    first = create(client)
    second = create(client, "Второе", completed=True)
    assert client.get("/todos/1").json() == first
    assert client.get("/todos").json() == [first, second]


def test_patch_updates_only_supplied_fields(client):
    create(client)
    response = client.patch("/todos/1", json={"title": " Обновлено "})
    assert response.status_code == 200
    assert response.json() == {"id": 1, "title": "Обновлено", "completed": False}


def test_patch_completed_from_true_to_false(client):
    create(client, completed=True)
    response = client.patch("/todos/1", json={"completed": False})
    assert response.status_code == 200
    assert response.json()["completed"] is False
    assert client.get("/todos/1").json()["completed"] is False


def test_empty_patch_on_missing_todo_returns_exact_404(client):
    response = client.patch("/todos/999", json={})
    assert response.status_code == 404
    assert response.json() == {"detail": "Todo not found"}


def test_empty_patch_is_rejected_without_changing_state(client):
    original = create(client)
    response = client.patch("/todos/1", json={})
    assert response.status_code == 400
    assert client.get("/todos/1").json() == original


@pytest.mark.parametrize("field", ["title", "completed"])
def test_explicit_null_is_rejected_without_changing_state(client, field):
    original = create(client)
    response = client.patch("/todos/1", json={field: None})
    assert response.status_code == 400
    assert client.get("/todos/1").json() == original


@pytest.mark.parametrize("field", ["title", "completed"])
def test_explicit_null_is_rejected_on_create(client, field):
    response = client.post("/todos", json={"title": "Invalid", field: None})
    assert response.status_code == 400
    assert client.get("/todos").json() == []


@pytest.mark.parametrize("title", ["", " ", "   ", "x" * 201])
def test_invalid_titles_are_rejected_without_changing_state(client, title):
    original = create(client)
    assert client.post("/todos", json={"title": title}).status_code == 422
    assert client.patch("/todos/1", json={"title": title}).status_code == 422
    assert client.get("/todos").json() == [original]


def test_200_character_title_is_trimmed_before_boundary_validation(client):
    response = client.post("/todos", json={"title": " " + "x" * 200 + " "})
    assert response.status_code == 201
    assert response.json() == {"id": 1, "title": "x" * 200, "completed": False}


def test_invalid_post_and_delete_do_not_consume_ids(client):
    first = create(client)
    assert client.post("/todos", json={"title": "   "}).status_code == 422
    assert client.post("/todos", json={"title": None}).status_code == 400
    assert client.delete("/todos/999").status_code == 404
    assert client.delete("/todos/1").status_code == 204
    assert client.delete("/todos/1").status_code == 404
    assert create(client, "Второе") == {"id": 2, "title": "Второе", "completed": False}
    assert client.get("/todos").json() == [{"id": 2, "title": "Второе", "completed": False}]
    assert first["id"] == 1


def test_missing_routes_return_exact_404(client):
    for method in ("get", "patch", "delete"):
        response = getattr(client, method)("/todos/999", **({"json": {"completed": True}} if method == "patch" else {}))
        assert response.status_code == 404
        assert response.json() == {"detail": "Todo not found"}


def test_delete_returns_204_with_empty_body(client):
    create(client)
    response = client.delete("/todos/1")
    assert response.status_code == 204
    assert response.content == b""
    assert client.get("/todos").json() == []
