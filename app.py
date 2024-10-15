from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from supabase import create_client, Client
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hashlib
import base64
import os
import io
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'

# Supabase setup
url: str = os.environ.get("SUPABASE_URL")
key: str = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(url, key)

class SimulatedCPABE:
    def __init__(self, policy):
        self.policy = policy
    
    def derive_key(self, attributes):
        attribute_string = ','.join(sorted(attributes))
        return hashlib.sha256(attribute_string.encode()).digest()

    def encrypt(self, content, policy, user_attributes):
        if set(user_attributes).issubset(set(policy)):
            key = self.derive_key(user_attributes)
            cipher = AES.new(key, AES.MODE_ECB)
            padded_content = pad(content, AES.block_size)
            encrypted_content = cipher.encrypt(padded_content)
            return base64.b64encode(encrypted_content).decode()
        else:
            raise Exception("User attributes do not satisfy the encryption policy")

    def decrypt(self, encrypted_content, policy, user_attributes):
        if set(user_attributes).issubset(set(policy)):
            key = self.derive_key(user_attributes)
            cipher = AES.new(key, AES.MODE_ECB)
            decrypted_content = cipher.decrypt(base64.b64decode(encrypted_content))
            return unpad(decrypted_content, AES.block_size)
        else:
            raise Exception("User attributes do not satisfy the decryption policy")

def encrypt_content(content, key, encryption_policy, user_attributes=None):
    if encryption_policy == 'AES':
        cipher = AES.new(key, AES.MODE_ECB)
        padded_content = pad(content, AES.block_size)
        encrypted_content = cipher.encrypt(padded_content)
        return base64.b64encode(encrypted_content).decode()
    elif encryption_policy == 'SHA256':
        return hashlib.sha256(content).hexdigest()
    elif encryption_policy == 'ABE':
        abe = SimulatedCPABE(policy=user_attributes)
        return abe.encrypt(content, user_attributes, user_attributes)

def decrypt_content(encrypted_content, key, encryption_policy, user_attributes=None):
    if encryption_policy == 'AES':
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted_content = cipher.decrypt(base64.b64decode(encrypted_content))
        return unpad(decrypted_content, AES.block_size)
    elif encryption_policy == 'SHA256':
        return "SHA256 encrypted content cannot be decrypted."
    elif encryption_policy == 'ABE':
        abe = SimulatedCPABE(policy=user_attributes)
        return abe.decrypt(encrypted_content, user_attributes, user_attributes)

@app.route('/')
def index():
    response = supabase.table('documents').select('*').execute()
    documents = response.data
    return render_template('index.html', documents=documents)

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        file = request.files['file']
        filename = file.filename
        owner = request.form['owner']
        encryption_policy = request.form['encryption_policy']
        user_attributes = request.form['attributes'].split(',')
        
        try:
            content = file.read()
            is_binary = isinstance(content, bytes)
        except Exception as e:
            flash(f"Error reading file: {str(e)}", "error")
            return redirect(url_for('upload'))

        if not is_binary:
            content = content.encode('utf-8')

        key = None
        encrypted_content = None

        try:
            if encryption_policy == 'ABE':
                abe = SimulatedCPABE(policy=user_attributes)
                encrypted_content = abe.encrypt(content, user_attributes, user_attributes)
                # For ABE, we don't store a key
            else:
                key = get_random_bytes(16)
                encrypted_content = encrypt_content(content, key, encryption_policy, user_attributes)
        except Exception as e:
            flash(f"Encryption failed: {str(e)}", "error")
            return redirect(url_for('upload'))

        if not encrypted_content:
            flash('Encryption failed, content is empty.', 'error')
            return redirect(url_for('upload'))

        data = {
            'content': encrypted_content,
            'encryption_policy': encryption_policy,
            'owner': owner,
            'is_binary': is_binary,
            'key': base64.b64encode(key).decode() if key else None,  # This will be None for ABE
            'filename': filename,
            'attributes': json.dumps(user_attributes)
        }

        try:
            response = supabase.table('documents').insert(data).execute()
            if response.data:
                flash('Document uploaded successfully!', 'success')
            else:
                flash('Error uploading document: No data returned from database.', 'error')
        except Exception as e:
            flash(f'Error uploading document to database: {str(e)}', 'error')

        return redirect(url_for('index'))

    return render_template('upload.html')

@app.route('/view/<int:id>', methods=['GET', 'POST'])
def view(id):
    response = supabase.table('documents').select('*').eq('id', id).execute()
    if not response.data:
        flash('Document not found.', 'error')
        return redirect(url_for('index'))

    document = response.data[0]

    if request.method == 'POST':
        try:
            if document['encryption_policy'] == 'SHA256':
                user_key = request.form['key']
                if user_key:
                    # Verify the key against the database
                    if user_key == document['key']:
                        flash(f'SHA256 Hash: {document["content"]}', 'success')
                    else:
                        flash('Invalid key.', 'error')
                else:
                    flash('Please provide a key for SHA256 verification.', 'error')
            elif document['encryption_policy'] == 'AES':
                user_key = request.form['key']
                if user_key:
                    try:
                        key = base64.b64decode(user_key)
                        decrypted_content = decrypt_content(document['content'], key, document['encryption_policy'])
                        return send_file(
                            io.BytesIO(decrypted_content),
                            as_attachment=True,
                            download_name=document['filename'],
                            mimetype='application/octet-stream'
                        )
                    except Exception as e:
                        flash('Invalid key or decryption failed.', 'error')
                else:
                    flash('Please provide a key for AES decryption.', 'error')
            elif document['encryption_policy'] == 'ABE':
                user_attributes = request.form['attributes'].split(',')
                stored_attributes = json.loads(document['attributes'])
                if set(user_attributes).issubset(set(stored_attributes)):
                    try:
                        decrypted_content = decrypt_content(document['content'], None, document['encryption_policy'], stored_attributes)
                        return send_file(
                            io.BytesIO(decrypted_content),
                            as_attachment=True,
                            download_name=document['filename'],
                            mimetype='application/octet-stream'
                        )
                    except Exception as e:
                        flash('Decryption failed.', 'error')
                else:
                    flash('Your attributes do not match the required attributes for this document.', 'error')
        except Exception as e:
            flash(f'Error processing the document: {str(e)}', 'error')

    return render_template('view.html', document=document)

if __name__ == '__main__':
    app.run(debug=True)