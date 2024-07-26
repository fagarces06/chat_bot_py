from fastapi import FastAPI, HTTPException
from typing import List
from pydantic import BaseModel
from passlib.context import CryptContext
import jwt

fake_db = {"users": {}}

app = FastAPI()


class Payload(BaseModel):
    numbers: List[int]


class BinarySearchPayload(BaseModel):
    numbers: List[int]
    target: int

class User(BaseModel):
    username: str
    password:str

#crear una funcion para decodificar el token y ver si el usuario esta autenticado revisando que el valor de "user" este en "fake_db" de usuarios. debe devolver el usuario autenticado o un status code 401 con un mensaje de errror "Credenciales inválidas"
def get_current_user(token: str):
    """
    Decodes a JWT token and retrieves the authenticated user from the fake database.
    
    Args:
        token (str): The JWT token to be decoded.
    
    Returns:
        dict: A dictionary containing the username of the authenticated user.
    
    Raises:
        HTTPException: If the token is invalid, expired, or the user is not found in the fake database.
    """
    try:
        payload = jwt.decode(token, "your_secret_key", algorithms=["HS256"])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=401, detail="Invalid authentication credentials"
            )
        if username not in fake_db["users"]:
            raise HTTPException(
                status_code=401, detail="Invalid authentication credentials"
            )
        return {"username": username}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


#crea una funcion post /register que reciba como entrada los siguientes valors: {username,password}. La paswoord debe ir encriptada con hash y la funcion retorno un status de 200 si se realiza con exito o 400 si se presento un error.
"""
Registers a new user in the fake database.

Args:
    user (User): A Pydantic model containing the username and password of the new user.

Returns:
    dict: A dictionary with a success message if the user was registered successfully.

Raises:
    HTTPException: If the username already exists in the fake database.
"""
@app.post("/register")
def register(user:User):
    print("ingreso a la funcion de register")
    if user.username in fake_db["users"]:
        raise HTTPException(status_code=400, detail="Username already exists")
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    hashed_password = pwd_context.hash(user.password)
    fake_db["users"][user.username] = {"password": hashed_password}
    return {"message": "User registered successfully"}


#Crea una ruta endpoint POST /login que recibe la siguiente informacion {username,password} y verfifica si el usuario existe en la fake_db y si la passwor es correcta. CUando el usuario existe y la password es correcta retorno a JWT token. Pero si el usuario no existe y la password es incorrecta retorno un status de 400
"""
Authenticates a user and returns a JWT token.

Args:
    user (User): A Pydantic model containing the username and password of the user.

Returns:
    dict: A dictionary containing the access token.

Raises:
    HTTPException: If the username does not exist in the fake database or the password is incorrect.
"""
@app.post("/login")
def login(user: User):
    if user.username not in fake_db["users"]:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    if not pwd_context.verify(user.password, fake_db["users"][user.username]["password"]):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    secret_key = "your_secret_key"  # Replace with a secure secret key
    token = jwt.encode({"sub": user.username}, secret_key, algorithm="HS256")
    return {"access_token": token}


# Ruta: /bubble-sort
# Método: POST
# Descripción: Recibe una lista de números y devuelve la lista ordenada utilizando el algoritmo de Bubble Sort.
# Entrada: {"numbers": [lista de números]}
# Salida: {"numbers": [lista de números ordenada]}
"""
Sorts a list of numbers using the Bubble Sort algorithm.

Args:
    payload (Payload): A Pydantic model containing the list of numbers to be sorted.
    token (str): The authentication token of the current user.

Returns:
    dict: A dictionary containing the sorted list of numbers.
"""
@app.post("/bubble-sort")
def bubble_sort(payload: Payload, token:str):

    get_current_user(token)
    numbers = payload.numbers
    n = len(numbers)
    for i in range(n):
        for j in range(0, n - i - 1):
            if numbers[j] > numbers[j + 1]:
                numbers[j], numbers[j + 1] = numbers[j + 1], numbers[j]
    return {"numbers": numbers}



#Ruta: /filter-even
#Método: POST
#Descripción: Recibe una lista de números y devuelve únicamente aquellos que son pares.
#Entrada: {"numbers": [lista de números]}
#Salida: {"even_numbers": [lista de números pares]}


"""
Filters a list of numbers and returns only the even numbers.

Args:
    payload (Payload): A Pydantic model containing the list of numbers to be filtered.
    token (str): The authentication token of the current user.

Returns:
    dict: A dictionary containing the list of even numbers.
"""
@app.post("/filter-even")
def filter_even(payload: Payload, token: str):
    get_current_user(token)
    numbers = payload.numbers
    even_numbers = [number for number in numbers if number % 2 == 0]
    return {"even_numbers": even_numbers}


#Ruta: /sum-elements
#Método: POST
#Descripción: Recibe una lista de números y devuelve la suma de sus elementos.
#Entrada: {"numbers": [lista de números]}
#Salida: {"sum": suma de los números}

"""
Calculates the sum of a list of numbers.

Args:
    payload (Payload): A Pydantic model containing the list of numbers to be summed.
    token (str): The authentication token of the current user.

Returns:
    dict: A dictionary containing the sum of the numbers.
""" 
@app.post("/sum-elements")
def sum_elements(payload: Payload, token: str):
    get_current_user(token)
    numbers = payload.numbers
    return {"sum": sum(numbers)}




#Ruta: /max-value
#Método: POST
#Descripción: Recibe una lista de números y devuelve el valor máximo.
#Entrada: {"numbers": [lista de números]}
#Salida:  {"max": número máximo}

"""
Finds the maximum value in a list of numbers.

Args:
    payload (Payload): A Pydantic model containing the list of numbers to be searched for the maximum value.
    token (str): The authentication token of the current user.

Returns:
    dict: A dictionary containing the maximum value in the list.
"""
@app.post("/max-value")
def max_value(payload: Payload, token: str):
    get_current_user(token)
    numbers = payload.numbers
    return {"max": max(numbers)}


#Ruta: /binary-search
#Método: POST
#Descripción: Recibe un número y una lista de números ordenados. Devuelve true y el índice si el número está en la lista, de lo contrario false y -1 como index.
#Entrada: {"numbers": [lista de números], "target": int}
#Salida:  {"found": booleano, "index": int}

"""
Performs a binary search on a sorted list of numbers to determine if a target number is present.

Args:
    payload (Payload): A Pydantic model containing the sorted list of numbers and the target number to be searched.
    token (str): The authentication token of the current user.

Returns:
    dict: A dictionary containing the result of the binary search.
"""
@app.post("/binary-search")
def binary_search(payload: Payload, token: str):
    get_current_user(token)
    numbers = payload.numbers
    target = payload.target
    left = 0
    right = len(numbers) - 1
    founded= False
    while left <= right:
        mid = (left + right) // 2
        if numbers[mid] == target:
            founded=True
            return {"found": True, "index": mid}
        elif numbers[mid] < target:
            left = mid + 1
        else:
            right = mid - 1
    if (founded ==False):
        return "The target was incorrectly found or the wrong index was returned"
    return {"found": False, "index": -1}


