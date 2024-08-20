from flask import Flask, request, jsonify
import docker
import uuid
import os
import redis
import hashlib
import secrets
from functools import wraps
import shlex
from flask_cors import CORS
import socket

""" def get_host_name_ip():
    try:
        host_name = socket.gethostname()
        host_ip = socket.gethostbyname(host_name)
        print("Hostname:", host_name)
        print("IP Address:", host_ip)
    except Exception as e:
        print("Unable to get Hostname and IP:", e) """

# Call the function
# get_host_name_ip()

app = Flask(__name__)
CORS(app)
docker_client = docker.from_env()
# redis_client = redis.Redis(host='localhost', port=6379, db=0)
redis_client = redis.Redis(host='redis', port=6379, db=0)

# API key management
def generate_api_key():
    return secrets.token_urlsafe(32)

def hash_api_key(api_key):
    return hashlib.sha256(api_key.encode()).hexdigest()

def store_api_key(api_key, user_id):
    hashed_key = hash_api_key(api_key)
    redis_client.hset('api_keys', hashed_key, user_id)

def get_user_id(api_key):
    hashed_key = hash_api_key(api_key)
    return redis_client.hget('api_keys', hashed_key)

def revoke_api_key(api_key):
    hashed_key = hash_api_key(api_key)
    redis_client.hdel('api_keys', hashed_key)

# Rate limiting
def is_rate_limited(user_id):
    key = f"rate_limit:{user_id}"
    count = redis_client.get(key)
    if count is None:
        redis_client.setex(key, 60, 1)  # 1 request per minute
        return False
    if int(count) >= 10:  # 10 requests per minute
        return True
    redis_client.incr(key)
    return False

# Authentication decorator
def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return jsonify({'error': 'API key is missing'}), 401
        user_id = get_user_id(api_key)
        if not user_id:
            return jsonify({'error': 'Invalid API key'}), 401
        if is_rate_limited(user_id):
            return jsonify({'error': 'Rate limit exceeded'}), 429
        return f(*args, **kwargs)
    return decorated_function

# Code execution

""" @app.route('/execute', methods=['POST'])
@require_api_key
def execute_code():
    code = request.json.get('code')
    language = request.json.get('language')

    if not code or not language:
        return jsonify({'error': 'Missing code or language'}), 400

    filename = f"{uuid.uuid4()}.{language}"
    with open(filename, 'w') as f:
        f.write(code)

    try:
        container = docker_client.containers.run(
            f"{language}-runner",
            f"python /code/{filename}",
            volumes={os.path.abspath(filename): {'bind': f'/code/{filename}', 'mode': 'ro'}},
            remove=True,
            mem_limit='100m',
            network_mode='none',
            timeout=10
        )
        
        output = container.decode('utf-8')
        return jsonify({'output': output})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        os.remove(filename) """

""" @app.route('/execute', methods=['POST'])
@require_api_key
def execute_code():
    code = request.json.get('code')
    language = request.json.get('language')

    language_mapping = {'python':'py',"java":'java',"javascript":'js'}

    if not code or not language:
        return jsonify({'error': 'Missing code or language'}), 400

    filename = f"{uuid.uuid4()}.{language_mapping[language]}"
    print(f"Writing code to file: {filename}")
    print(f"Code content: {code}")
    with open(filename, 'w') as f:
        f.write(code)

    container_name = f"code_exec_{uuid.uuid4().hex}"
    try:
        container = docker_client.containers.run(
            # f"{language}-runner",
            "python:3.9-slim",  # Using official Python image
            f"/bin/sh -c 'python /code/{filename} 2>&1'",
            volumes={os.path.abspath(filename): {'bind': f'/code/{filename}', 'mode': 'ro'}},
            mem_limit='100m',
            network_mode='none',
            name=container_name,
            detach=True
        )

        container = docker_client.containers.run(
            f"{language}-runner",
            # giving code directly to the python interpreter without writing the code to a file
            f"python -c {code}",
            volumes={os.path.abspath(filename): {'bind': f'/code/{filename}', 'mode': 'ro'}},
            mem_limit='100m',
            network_mode='none',
            name=container_name,
            detach=True
        )

        # Wait for the container to finish
        result = container.wait(timeout=10)  # 10 seconds timeout
        print(result)

        logs = container.logs().decode('utf-8')
        
        if result['StatusCode'] != 0:
            return jsonify({'error': f"Execution failed. Exit code: {result['StatusCode']}", 'output': logs}), 500
        
        return jsonify({'output': logs})
    except docker.errors.ContainerError as e:
        return jsonify({'error': f"Container error: {str(e)}"}), 500
    except Exception as e:
        return jsonify({'error': f"Unexpected error: {str(e)}"}), 500
    finally:
        try:
            container = docker_client.containers.get(container_name)
            container.remove(force=True)
        except:
            pass  # Container might already be removed or not exist 
        os.remove(filename) """

@app.route('/execute', methods=['POST'])
@require_api_key
def execute_code():
    code = request.json.get('code')
    language = request.json.get('language')

    if not code or not language:
        return jsonify({'error': 'Missing code or language'}), 400

    if language.lower() != 'python':
        return jsonify({'error': 'Only Python is supported at the moment'}), 400

    container_name = f"code_exec_{uuid.uuid4().hex}"
    try:
        # Wrap the code in a main function and call it
        wrapped_code = f"""
def main():
    {code.replace(chr(10), chr(10) + '    ')}

if __name__ == "__main__":
    main()
"""
        container = docker_client.containers.run(
            f"{language}-runner",
            # "python:3.9-slim",  # Using official Python image
            ["python", "-c", wrapped_code],
            mem_limit='100m',
            network_mode='none',
            name=container_name,
            detach=True
        )

        # Wait for the container to finish
        result = container.wait(timeout=10)  # 10 seconds timeout
        print(result)

        logs = container.logs().decode('utf-8')
        
        if result['StatusCode'] != 0:
            return jsonify({'error': f"Execution failed. Exit code: {result['StatusCode']}", 'output': logs}), 500
        
        return jsonify({'output': logs})
    except docker.errors.ContainerError as e:
        return jsonify({'error': f"Container error: {str(e)}"}), 500
    except Exception as e:
        return jsonify({'error': f"Unexpected error: {str(e)}"}), 500
    finally:
        try:
            container = docker_client.containers.get(container_name)
            container.remove(force=True)
        except:
            pass  # Container might already be removed or not exist



# API key management endpoints
@app.route('/api_key', methods=['POST'])
def create_api_key():
    user_id = request.json.get('user_id')
    if not user_id:
        return jsonify({'error': 'User ID is required'}), 400
    
    api_key = generate_api_key()
    store_api_key(api_key, user_id)
    return jsonify({'api_key': api_key})

@app.route('/api_key', methods=['DELETE'])
@require_api_key
def delete_api_key():
    api_key = request.headers.get('X-API-Key')
    revoke_api_key(api_key)
    return jsonify({'message': 'API key revoked successfully'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)