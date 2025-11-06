import pytest
import requests
import random
import string

def get_auth_token():
    # Crear un usuario aleatorio
    username = ''.join(random.choices(string.ascii_letters, k=10))
    user_data = {
        "username": username,
        "password": "Password123!",
        "email": f"{username}@test.com",
        "first_name": "Test",
        "last_name": "User"
    }
    
    # Registrar usuario
    response = requests.post("http://localhost:5000/users", json=user_data)
    assert response.status_code == 201, "No se pudo crear el usuario"
    
    # Login para obtener token
    login_response = requests.post("http://localhost:5000/auth/login", 
                                 json={"username": username, "password": "Password123!"})
    assert login_response.status_code == 200, "No se pudo hacer login"
    return login_response.json()["token"]

@pytest.fixture(scope="module")
def auth_token():
    return get_auth_token()

def test_sql_injection_in_invoices(auth_token):
    # Test casos de inyección SQL en la búsqueda de facturas
    payloads = [
        "' OR '1'='1",                              # Inyección SQL básica
        "'; DROP TABLE invoices; --",               # Intento de borrar tabla
        "' UNION SELECT * FROM users; --",          # Intento de obtener datos de otra tabla
        "' OR 'x'='x",                             # Otra variante de inyección
        "1' OR '1' = '1'))/*",                     # Inyección con comentarios
        "1' OR '1' = '1')) LIMIT 1/*"              # Inyección con LIMIT
    ]
    
    headers = {"Authorization": f"Bearer {auth_token}"}
    
    # Probar cada payload
    for sql_injection in payloads:
        # Intentar inyección en el parámetro status
        response = requests.get(
            "http://localhost:5000/invoices",
            params={"status": sql_injection},
            headers=headers
        )
        
        # La aplicación debería rechazar las inyecciones SQL
        # o manejarlas de forma segura sin exponer datos
        assert response.status_code in [400, 401, 403, 200], \
            f"Respuesta inesperada para inyección '{sql_injection}'"
        
        if response.status_code == 200:
            data = response.json()
            # Si devuelve datos, verificar que no haya datos no autorizados
            assert len(data) == 0 or all('status' in inv for inv in data), \
                f"Posible inyección SQL exitosa con '{sql_injection}'"

def test_invoice_filter_validation(auth_token):
    # Probar filtros válidos para asegurar que la funcionalidad legítima sigue funcionando
    valid_statuses = ['paid', 'unpaid', 'pending']
    headers = {"Authorization": f"Bearer {auth_token}"}
    
    for status in valid_statuses:
        response = requests.get(
            "http://localhost:5000/invoices",
            params={"status": status},
            headers=headers
        )
        
        # Verificar que las consultas válidas son aceptadas
        assert response.status_code == 200, \
            f"El filtro válido '{status}' fue rechazado"
        
        # Si hay resultados, verificar que coinciden con el filtro
        if response.status_code == 200:
            data = response.json()
            if len(data) > 0:
                assert all(inv.get('status') == status for inv in data), \
                    f"Los resultados no coinciden con el filtro '{status}'"

def test_sql_injection_in_invoice_id(auth_token):
    # Test de inyección SQL en el ID de factura
    payloads = [
        "1' OR '1'='1",
        "1; SELECT * FROM users",
        "1' UNION SELECT username, password FROM users --",
        "1' AND (SELECT COUNT(*) FROM users) > 0 --"
    ]
    
    headers = {"Authorization": f"Bearer {auth_token}"}
    
    for sql_injection in payloads:
        response = requests.get(
            f"http://localhost:5000/invoices/{sql_injection}",
            headers=headers
        )
        
        # La aplicación debería rechazar o manejar de forma segura las inyecciones
        assert response.status_code in [400, 401, 403, 404], \
            f"Posible vulnerabilidad con payload: {sql_injection}"
