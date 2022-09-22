from dataclasses import dataclass
from fastapi.testclient import TestClient
from .main import app
import random
import time

client = TestClient(app)

fake_user_number = random.randint(0, 99999)

class TestFakeData:
    auth_signup_request_body = {
        "name": "User",
        "email": f"user{fake_user_number}@example.com",
        "password": "strong-password^999",
        "passwordConfirm": "strong-password^999"
    }
    auth_login_request_body ={
        "email": f"user_test@example.com",
        "password": "password123",
    }

def test_read_root():
    response = client.get("/")
    assert response.status_code == 200

def test_read_api():
    response = client.get("/api")
    assert response.json() == {"message": "hello from @your-api"}

def test_v1_auth_signup():
    response = client.post("/api/v1/auth/signup", json=TestFakeData.auth_signup_request_body)
    assert response.status_code == 201

def test_v1_auth_signup_bad_password_confirm():
    data = TestFakeData.auth_signup_request_body.copy()
    data["passwordConfirm"] = "strong-password^xxx"
    response = client.post("/api/v1/auth/signup", json=data)
    assert response.status_code == 409

def test_v1_auth_login():
    response = client.post("/api/v1/auth/login", json=TestFakeData.auth_login_request_body)
    assert response.status_code == 200

def test_v1_auth_login_bad_password():
    data = TestFakeData.auth_login_request_body.copy()
    data["password"] = "password1234"
    response = client.post("/api/v1/auth/login", json=data)
    assert response.status_code == 400

def test_v1_auth_refresh_acess_token():
    response = client.get("/api/v1/auth/refresh", json=TestFakeData.auth_login_request_body)
    assert response.status_code == 200

def test_v1_user_get_current_user_data():
    response = client.get("/api/v1/user/")
    res_data = response.json()
    assert res_data["data"]["user"]["email"] == TestFakeData.auth_login_request_body["email"]
    assert res_data["data"]["user"]["name"] == TestFakeData.auth_signup_request_body["name"]
    assert response.status_code == 200

def test_v1_auth_logout():
    response = client.get("/api/v1/auth/logout")
    assert response.status_code == 200

def test_v1_user_delete():
    _login_response = client.post("/api/v1/auth/login", json=TestFakeData.auth_login_request_body)
    response = client.delete("/api/v1/user/")
    assert response.status_code == 200
