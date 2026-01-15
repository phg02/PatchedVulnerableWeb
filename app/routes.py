from flask import Blueprint, render_template, request, session, redirect, url_for, make_response, send_file, current_app, flash, escape
from werkzeug.utils import secure_filename
from app.database import get_db
import os
import requests
import zipfile
import errno
import io
import subprocess
import re
from urllib.parse import urlparse
from email_validator import validate_email, EmailNotValidError
import bleach

main_bp = Blueprint('main', __name__)
api_bp = Blueprint('api', __name__, url_prefix='/api')

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

def validate_username(username):
	"""Validate username - alphanumeric and underscores only, 3-20 characters"""
	if not username or len(username) < 3 or len(username) > 20:
		return False, "Username must be 3-20 characters"
	if not re.match(r'^[a-zA-Z0-9_]+$', username):
		return False, "Username can only contain letters, numbers, and underscores"
	return True, None

def validate_email_format(email):
	"""Validate email format"""
	try:
		validate_email(email)
		return True, None
	except EmailNotValidError as e:
		return False, str(e)

def validate_password(password):
	"""Validate password - minimum 8 characters"""
	if not password or len(password) < 8:
		return False, "Password must be at least 8 characters"
	return True, None

def is_safe_url(url):
	"""Validate URL to prevent SSRF attacks"""
	dangerous_schemes = ['data', 'javascript', 'file', 'ftp', 'gopher', 'telnet']
	
	try:
		parsed = urlparse(url)
		if parsed.scheme.lower() in dangerous_schemes:
			return False
		if parsed.hostname in ['127.0.0.1', 'localhost', '0.0.0.0']:
			return False
		if parsed.hostname and parsed.hostname.startswith(('10.', '172.16.', '192.168.')):
			return False
		return True
	except:
		return False

def sanitize_html(text):
	"""Sanitize HTML content to prevent XSS"""
	allowed_tags = ['p', 'br', 'strong', 'em', 'u', 'a']
	allowed_attrs = {'a': ['href', 'title']}
	return bleach.clean(text, tags=allowed_tags, attributes=allowed_attrs, strip=True)

def unzip(zip_file, extraction_path):
	"""Unzip files from a zip file"""
	try:
		files = []
		with zipfile.ZipFile(zip_file, "r") as z:
			for fileinfo in z.infolist():
				filename = fileinfo.filename
				dat = z.open(filename, "r")
				files.append(filename)
				outfile = os.path.join(extraction_path, filename)
				if not os.path.exists(os.path.dirname(outfile)):
					try:
						os.makedirs(os.path.dirname(outfile))
					except OSError as exc:
						if exc.errno != errno.EEXIST:
							pass
				if not outfile.endswith("/"):
					with io.open(outfile, mode='wb') as f:
						f.write(dat.read())
				dat.close()
		return files
	except Exception as e:
		raise Exception(f"Unzipping Error: {str(e)}")

def html_escape(text):
	"""Escape HTML characters"""
	html_escape_table = {
		"&": "&amp;",
		'"': "&quot;",
		"'": "&apos;",
		">": "&gt;",
		"<": "&lt;",
	}
	return "".join(html_escape_table.get(c, c) for c in text)

def allowed_file(filename):
	"""Check if file extension is allowed for zip"""
	return '.' in filename and filename.rsplit('.', 1)[1].lower() in ['zip']

def get_external_url(endpoint):
	"""Generate external URL that respects reverse proxy headers"""
	base_url = url_for(endpoint, _external=False)
	
	forwarded_host = request.headers.get('X-Forwarded-Host')
	forwarded_port = request.headers.get('X-Forwarded-Port')
	forwarded_proto = request.headers.get('X-Forwarded-Proto', 'http')
	
	if forwarded_host and forwarded_port:
		return f"{forwarded_proto}://{forwarded_host}:{forwarded_port}{base_url}"
	elif forwarded_host:
		return f"{forwarded_proto}://{forwarded_host}{base_url}"
	else:
		return url_for(endpoint, _external=True)


@main_bp.route('/')
def index():
	return render_template('index.html')

@main_bp.route('/signin', methods=['GET'])
def signin_page():
	return render_template('signin.html')

@main_bp.route('/signin', methods=['POST'])
def signin():
	username = request.form.get('username', '').strip()
	password = request.form.get('password', '').strip()
	
	error = None
	
	if not username:
		error = 'Username is required.'
	elif not password:
		error = 'Password is required.'
	
	if error:
		return render_template('signin.html', error=error)
	
	db = get_db()
	
	user = db.execute(
		'SELECT * FROM users WHERE username = ? AND password = ?',
		(username, password)
	).fetchone()
	
	if user:
		session.clear()
		session['user_id'] = user['id']
		session['username'] = user['username']
		session['role'] = user['role']
		session.permanent = True
		
		if user['role'] == 'admin':
			redirect_url = get_external_url('main.admin_users')
		else:
			redirect_url = get_external_url('main.index')
		
		resp = make_response(redirect(redirect_url))
		is_secure = os.environ.get('FLASK_ENV') == 'production'
		resp.set_cookie('user_id', str(user['id']), httponly=True, secure=is_secure, samesite='Lax' if not is_secure else 'Strict')
		resp.set_cookie('access_token', 'example-access-token', httponly=True, secure=is_secure, samesite='Lax' if not is_secure else 'Strict')
		resp.set_cookie('refresh_token', 'example-refresh-token', httponly=True, secure=is_secure, samesite='Lax' if not is_secure else 'Strict')
		return resp
	
	return render_template('signin.html', error='Invalid username or password')

@main_bp.route('/signup', methods=['GET'])
def signup_page():
	return render_template('signup.html')

@main_bp.route('/signup', methods=['POST'])
def signup():
	username = request.form.get('username', '').strip()
	email = request.form.get('email', '').strip()
	password = request.form.get('password', '').strip()
	confirm = request.form.get('confirm', '').strip()
	
	error = None
	
	if not username:
		error = 'Username is required.'
	else:
		is_valid, validation_error = validate_username(username)
		if not is_valid:
			error = validation_error
	
	if error is None:
		if not email:
			error = 'Email is required.'
		else:
			is_valid, validation_error = validate_email_format(email)
			if not is_valid:
				error = validation_error
	
	if error is None:
		if not password:
			error = 'Password is required.'
		else:
			is_valid, validation_error = validate_password(password)
			if not is_valid:
				error = validation_error
	
	if error is None and password != confirm:
		error = 'Passwords do not match.'
	
	if error is None:
		db = get_db()
		try:
			db.execute(
				'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
				(username, email, password, 'user')
			)
			db.commit()
			return redirect(url_for('main.signin_page'))
		except db.IntegrityError:
			error = 'Email or username already registered.'
	
	return render_template('signup.html', error=error)

@main_bp.route('/logout')
def logout():
	session.clear()
	resp = make_response(redirect(get_external_url('main.index')))
	resp.set_cookie('user_id', '', expires=0)
	resp.set_cookie('access_token', '', expires=0)
	resp.set_cookie('refresh_token', '', expires=0)
	return resp

@main_bp.route('/todos')
def todos():
	if not session.get('user_id'):
		return redirect(url_for('main.signin_page'))
	
	db = get_db()
	todos = db.execute('SELECT * FROM todos ORDER BY created_at DESC').fetchall()
	return render_template('todos.html', todos=todos)

@main_bp.route('/todos/add', methods=['POST'])
def add_todo():
	if not session.get('user_id'):
		return redirect(url_for('main.signin_page'))
	
	title = request.form.get('title', '').strip()
	description = request.form.get('description', '').strip()
	due_date = request.form.get('due_date', '').strip()
	
	error = None
	
	if not title:
		error = 'Title is required.'
	elif len(title) > 255:
		error = 'Title is too long.'
	elif description and len(description) > 1000:
		error = 'Description is too long.'
	
	if error:
		return redirect(url_for('main.todos')) if not error else render_template('todos.html', error=error)
	
	title = sanitize_html(title)
	description = sanitize_html(description) if description else ''
	
	db = get_db()

	db.execute(
		'INSERT INTO todos (title, description, due_date) VALUES (?, ?, ?)',
		(title, description, due_date)
	)
	db.commit()
	
	return redirect(url_for('main.todos'))

@main_bp.route('/todos/delete/<int:todo_id>')
def delete_todo(todo_id):
	if not session.get('user_id'):
		return redirect(url_for('main.signin_page'))
	
	if not isinstance(todo_id, int) or todo_id <= 0:
		return redirect(url_for('main.todos'))
	
	db = get_db()
	db.execute('DELETE FROM todos WHERE id = ?', (todo_id,))
	db.commit()
	
	return redirect(url_for('main.todos'))

@main_bp.route('/todos/search')
def search_todos():
	if not session.get('user_id'):
		return redirect(url_for('main.signin_page'))
	
	search = request.args.get('q', '').strip()
	db = get_db()
	
	if search:
		if len(search) > 255:
			search = search[:255]
		
		todos = db.execute(
			'SELECT * FROM todos WHERE title LIKE ? OR description LIKE ?',
			(f'%{search}%', f'%{search}%')
		).fetchall()
	else:
		todos = db.execute('SELECT * FROM todos ORDER BY created_at DESC').fetchall()
	
	return render_template('todos.html', todos=todos, search=escape(search))

@main_bp.route('/notes')
def notes():
	if not session.get('user_id'):
		return redirect(url_for('main.signin_page'))
	
	if session.get('role') == 'admin':
		return render_template('index.html', error='Notes feature is not available for admin users.')
	
	filename = os.path.join(BASE_DIR, "shared_notes.txt")
	output = ""
	error = ""
	
	try:
		with open(filename, 'r', encoding='utf-8') as f:
			output = f.read()
	except FileNotFoundError:
		error = "Notes file not found"
	except Exception as e:
		error = "Error reading notes file"
	
	return render_template('notes.html', filename=filename, output=escape(output), error=error)

@main_bp.route('/notes/search', methods=['POST'])
def search_notes():
	if not session.get('user_id'):
		return redirect(url_for('main.signin_page'))
	
	if session.get('role') == 'admin':
		return render_template('index.html', error='Notes feature is not available for admin users.')
	
	filename = os.path.join(BASE_DIR, "shared_notes.txt")
	search_term = request.form.get('search_term', '').strip()
	output = ""
	error = ""
	
	if search_term:
		if len(search_term) > 255:
			search_term = search_term[:255]
		
		try:
			result = subprocess.run(
				['grep', '-i', search_term, filename],
				capture_output=True,
				text=True,
				timeout=5,
				shell=False
			)
			
			if result.returncode == 0:
				output = result.stdout.rstrip('\n')
			elif result.returncode == 1:
				output = ""
			else:
				error = "Error searching notes file"
		except FileNotFoundError:
			error = "Notes file not found"
		except subprocess.TimeoutExpired:
			error = "Search operation timed out"
		except Exception as e:
			error = "Error searching notes file"
		
		return render_template('notes.html', filename=filename, search_term=escape(search_term), output=escape(output), error=error, is_search=True)
	else:
		try:
			with open(filename, 'r', encoding='utf-8') as f:
				output = f.read()
		except FileNotFoundError:
			error = "Notes file not found"
		except Exception as e:
			error = "Error reading notes file"
		
		return render_template('notes.html', filename=filename, output=escape(output), error=error)

@main_bp.route('/notes/clear')
def clear_search():
	if not session.get('user_id'):
		return redirect(url_for('main.signin_page'))
	
	return redirect(url_for('main.notes'))

@main_bp.route('/admin/users')
def admin_users():
	if request.remote_addr in ['127.0.0.1', '::1', 'localhost']:
		db = get_db()
		users = db.execute('SELECT id, username, email, role, created_at FROM users ORDER BY created_at DESC').fetchall()
		return render_template('admin_users.html', users=users)
        
	if not session.get('user_id'):
		return redirect(url_for('main.signin_page'))
	
	if session.get('role') != 'admin':
		return redirect(url_for('main.todos'))
	
	db = get_db()
	users = db.execute('SELECT id, username, email, role, created_at FROM users ORDER BY created_at DESC').fetchall()
	return render_template('admin_users.html', users=users)

@main_bp.route('/admin/users/delete/<int:user_id>', methods=['POST'])
def delete_user(user_id):
	if request.remote_addr in ['127.0.0.1', '::1', 'localhost']:
		db = get_db()
		db.execute('DELETE FROM users WHERE id = ?', (user_id,))
		db.commit()
		return redirect(url_for('main.admin_users'))

	if not session.get('user_id'):
		return redirect(url_for('main.signin_page'))
	
	if session.get('role') != 'admin':
		return render_template('index.html', error='Access denied. Admin only.')
	
	if user_id == session.get('user_id'):
		return render_template('admin_users.html', error='Cannot delete your own account.')
	
	db = get_db()
	db.execute('DELETE FROM users WHERE id = ?', (user_id,))
	db.commit()
	
	return redirect(url_for('main.admin_users'))

@main_bp.route('/file/<path:filename>')
def unsafe_static(filename):
	return send_file(filename)

@main_bp.route('/upload', methods=['GET', 'POST'])
def upload_file():
	if not session.get('user_id'):
		return redirect(url_for('main.signin_page'))
	
	if request.method == 'POST':
		if 'file' not in request.files:
			return render_template('files.html', error='No file selected', uploaded_files=get_uploaded_files())
		
		f = request.files['file']
		
		if f.filename == '':
			return render_template('files.html', error='No file selected', uploaded_files=get_uploaded_files())
		
		if f:
			filename = secure_filename(f.filename)
			if not filename:
				return render_template('files.html', error='Invalid filename', uploaded_files=get_uploaded_files())
			
			filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
			
			try:
				f.save(filepath)
				return render_template('files.html', success='File uploaded successfully', uploaded_files=get_uploaded_files())
			except Exception as e:
				return render_template('files.html', error='Error uploading file', uploaded_files=get_uploaded_files())
	
	return render_template('files.html', uploaded_files=get_uploaded_files())

@main_bp.route('/files', methods=['GET'])
def read_file():
	if not session.get('user_id'):
		return redirect(url_for('main.signin_page'))
	
	file = request.args.get('file', '').strip()
	
	if not file:
		return redirect(url_for('main.upload_file'))
	
	try:
		if file.startswith('/') or '..' in file or file.startswith('~'):
			return render_template('files.html', error='Invalid file path', uploaded_files=get_uploaded_files())
		
		filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], secure_filename(file))
		upload_folder = os.path.abspath(current_app.config['UPLOAD_FOLDER'])
		filepath = os.path.abspath(filepath)
		
		if not filepath.startswith(upload_folder):
			return render_template('files.html', error='Invalid file path', uploaded_files=get_uploaded_files())
		
		if not os.path.exists(filepath) or not os.path.isfile(filepath):
			return render_template('files.html', error='File not found', uploaded_files=get_uploaded_files())
		
		with open(filepath, 'r', encoding='utf-8') as f:
			content = f.read()
		
		return render_template('view_file.html', filename=secure_filename(file), content=escape(content))
	except Exception as e:
		return render_template('files.html', error='Error reading file', uploaded_files=get_uploaded_files())

def get_uploaded_files():
	"""Get list of uploaded files"""
	upload_folder = current_app.config['UPLOAD_FOLDER']
	if not os.path.exists(upload_folder):
		return []
	return os.listdir(upload_folder)

@main_bp.route('/upload-zip', methods=['GET', 'POST'])
def upload_zip():
	if not session.get('user_id'):
		return redirect(url_for('main.signin_page'))
	
	if request.method == 'POST':
		if 'file' not in request.files:
			return render_template('upload_zip.html', error='No file part')
		
		file_uploaded = request.files['file']
		
		if file_uploaded.filename == '':
			return render_template('upload_zip.html', error='No file selected')
		
		if file_uploaded and allowed_file(file_uploaded.filename):
			extraction_path = current_app.config['UPLOAD_FOLDER']
			filename = secure_filename(file_uploaded.filename)
			write_to_file = os.path.join(extraction_path, filename)
			file_uploaded.save(write_to_file)
			
			try:
				extracted_files = unzip(write_to_file, extraction_path)
				message = f'Zip file uploaded and extracted. {len(extracted_files)} files extracted.'
				return render_template('upload_zip.html', success=message, extracted_files=extracted_files)
			except Exception as e:
				return render_template('upload_zip.html', error=str(e))
		else:
			return render_template('upload_zip.html', error='Only .zip files are allowed')
	
	return render_template('upload_zip.html')

@main_bp.route('/ssrf', methods=['GET', 'POST'])
def follow_url():
	if not session.get('user_id'):
		return redirect(url_for('main.signin_page'))
	
	url = request.args.get('url', '').strip()
	content = ''
	error = ''
	
	if request.method == 'POST':
		url = request.form.get('url', '').strip()
	
	if url:
		if not is_safe_url(url):
			error = 'Invalid or unsafe URL. Cannot access this resource.'
			return render_template('ssrf.html', url='', content='', error=error)
		
		try:
			response = requests.get(url, timeout=5, verify=True)
			if len(response.text) > 50000:
				error = 'Response content is too large'
			else:
				content = escape(response.text[:50000])
		except requests.exceptions.Timeout:
			error = 'Request timed out'
		except requests.exceptions.ConnectionError:
			error = 'Connection error'
		except Exception as e:
			error = 'Error fetching URL'
	else:
		if request.method == 'POST' or (request.method == 'GET' and 'url' in request.args):
			error = 'No URL parameter provided'
	
	return render_template('ssrf.html', url=escape(url), content=content, error=error)

@main_bp.route('/delete-file/<filename>', methods=['POST'])
def delete_file(filename):
	if not session.get('user_id'):
		return redirect(url_for('main.signin_page'))
	
	try:
		filename = secure_filename(filename)
		if not filename:
			return render_template('files.html', error='Invalid filename', uploaded_files=get_uploaded_files())
		
		filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
		upload_folder = os.path.abspath(current_app.config['UPLOAD_FOLDER'])
		filepath = os.path.abspath(filepath)
		if not filepath.startswith(upload_folder):
			return render_template('files.html', error='Invalid file path', uploaded_files=get_uploaded_files())
		
		if os.path.exists(filepath) and os.path.isfile(filepath):
			os.remove(filepath)
			return redirect(url_for('main.upload_file'))
		else:
			return render_template('files.html', error='File not found', uploaded_files=get_uploaded_files())
	except Exception as e:
		return render_template('files.html', error='Error deleting file', uploaded_files=get_uploaded_files())

