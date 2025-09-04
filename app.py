from flask import Flask, request, render_template, redirect, url_for, flash, session, jsonify
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Attr
from datetime import datetime, timedelta
import uuid
import boto3
import pytz
import hmac
import hashlib
import base64
import json
import os
import uuid
import io
from werkzeug.utils import secure_filename
from PIL import Image

app = Flask(__name__)

def get_aws_config():
    """Get AWS configuration based on environment"""
    config = {}
    
    # Check if we're using LocalStack
    endpoint_url = os.getenv('AWS_ENDPOINT_URL')
    region = os.getenv('AWS_REGION', 'us-east-1')
    
    if endpoint_url:
        # LocalStack configuration
        config['endpoint_url'] = endpoint_url
        config['region_name'] = region
        config['aws_access_key_id'] = os.getenv('AWS_ACCESS_KEY_ID', 'test')
        config['aws_secret_access_key'] = os.getenv('AWS_SECRET_ACCESS_KEY', 'test')
        print(f"Using LocalStack at {endpoint_url}")
    else:
        # Real AWS configuration
        config['region_name'] = region
        # AWS credentials will be picked up from environment or IAM role
        print("Using real AWS services")
    
    return config

def get_secrets():
    """Get secrets from environment variables or AWS Secrets Manager"""
    
    # Try to get from environment variables first (for LocalStack)
    if os.getenv('FLASK_SECRET_KEY'):
        return {
            'FLASK_SECRET_KEY': os.getenv('FLASK_SECRET_KEY'),
            'USER_POOL_ID': os.getenv('USER_POOL_ID'),
            'APP_CLIENT_ID': os.getenv('APP_CLIENT_ID'),
            'CLIENT_SECRET': os.getenv('CLIENT_SECRET')
        }
    
    # Fallback to AWS Secrets Manager
    secret_name = os.getenv('SECRET_NAME', 'equipment-app/config')
    aws_config = get_aws_config()
    
    try:
        # สร้าง Secrets Manager client
        session = boto3.session.Session()
        client_kwargs = {
            'service_name': 'secretsmanager',
            'region_name': aws_config['region_name']
        }
        
        if 'endpoint_url' in aws_config:
            client_kwargs['endpoint_url'] = aws_config['endpoint_url']
            client_kwargs['aws_access_key_id'] = aws_config['aws_access_key_id']
            client_kwargs['aws_secret_access_key'] = aws_config['aws_secret_access_key']
        
        client = session.client(**client_kwargs)
        
        # ดึงค่า Secret
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            return json.loads(secret)
    except ClientError as e:
        print(f"Error retrieving secrets: {e}")
        # Return default values for development
        return {
            'FLASK_SECRET_KEY': 'development-secret-key',
            'USER_POOL_ID': 'us-east-1_localstack',
            'APP_CLIENT_ID': 'localstack-client',
            'CLIENT_SECRET': 'localstack-secret'
        }


# Get AWS configuration
aws_config = get_aws_config()

# ดึงค่า Secrets
secrets = get_secrets()

# ตั้งค่า Flask secret key
app.secret_key = secrets.get('FLASK_SECRET_KEY')

# AWS Cognito Configuration
USER_POOL_ID = secrets.get('USER_POOL_ID')
APP_CLIENT_ID = secrets.get('APP_CLIENT_ID')
CLIENT_SECRET = secrets.get('CLIENT_SECRET')

# Create AWS clients with proper configuration
cognito_kwargs = {
    'service_name': 'cognito-idp',
    'region_name': aws_config['region_name']
}
if 'endpoint_url' in aws_config:
    cognito_kwargs['endpoint_url'] = aws_config['endpoint_url']
    cognito_kwargs['aws_access_key_id'] = aws_config['aws_access_key_id']
    cognito_kwargs['aws_secret_access_key'] = aws_config['aws_secret_access_key']

cognito = boto3.client(**cognito_kwargs)

# DynamoDB Configuration
dynamodb_kwargs = {
    'service_name': 'dynamodb',
    'region_name': aws_config['region_name']
}
if 'endpoint_url' in aws_config:
    dynamodb_kwargs['endpoint_url'] = aws_config['endpoint_url']
    dynamodb_kwargs['aws_access_key_id'] = aws_config['aws_access_key_id']
    dynamodb_kwargs['aws_secret_access_key'] = aws_config['aws_secret_access_key']

dynamodb = boto3.resource(**dynamodb_kwargs)
EquipmentTable = dynamodb.Table(os.getenv('EQUIPMENT_TABLE', 'Equipment'))
BorrowReturnRecordsTable = dynamodb.Table(os.getenv('BORROW_RETURN_RECORDS_TABLE', 'BorrowReturnRecords'))

def get_s3_client():
    """Create S3 client with proper configuration"""
    s3_kwargs = {
        'service_name': 's3',
        'region_name': aws_config['region_name']
    }
    if 'endpoint_url' in aws_config:
        s3_kwargs['endpoint_url'] = aws_config['endpoint_url']
        s3_kwargs['aws_access_key_id'] = aws_config['aws_access_key_id']
        s3_kwargs['aws_secret_access_key'] = aws_config['aws_secret_access_key']
    
    return boto3.client(**s3_kwargs)

def is_localstack_environment():
    """Check if running in LocalStack environment"""
    return os.getenv('AWS_ENDPOINT_URL') is not None

def get_hardcoded_users():
    """Get hardcoded users for LocalStack bypass"""
    return {
        'testuser': {
            'password': 'password',
            'email': 'test@example.com',
            'name': 'Test User',
            'role': 'user',
            'faculty': 'Engineering',
            'student_id': 'TEST001',
            'phone': '+66812345678',
            'club_member': 'Yes',
            'dob': '2000-01-01'
        },
        'admin': {
            'password': 'admin',
            'email': 'admin@example.com', 
            'name': 'Admin User',
            'role': 'admin',
            'faculty': 'Administration',
            'student_id': 'ADMIN001',
            'phone': '+66812345679',
            'club_member': 'Yes',
            'dob': '1990-01-01'
        }
    }

def validate_token():
    """Validate the access token in the session"""
    if 'username' in session and 'access_token' in session:
        # Check if we're in LocalStack environment and using fake token
        if is_localstack_environment() and session['access_token'].startswith('fake_token_'):
            # Fake token validation - always valid if format is correct
            if 'user_data' in session:
                return True
            else:
                session.clear()
                return False
        
        try:
            # Try to use the token to get user info from Cognito
            cognito.get_user(AccessToken=session['access_token'])
            return True
        except ClientError as e:
            error_message = e.response['Error']['Message']
            print(f"Token validation error: {error_message}")
            # Clear the session if token is expired or invalid
            session.clear()
            return False
    return False

def get_secret_hash(username, client_id, client_secret):
    message = username + client_id
    dig = hmac.new(
        str(client_secret).encode('utf-8'),
        msg=str(message).encode('utf-8'),
        digestmod=hashlib.sha256
    ).digest()
    return base64.b64encode(dig).decode()

def get_profile_image_url():
    """ฟังก์ชันช่วยสำหรับดึง URL รูปโปรไฟล์"""
    profile_image_url = None
    if 'username' in session and 'access_token' in session:
        try:
            # Check if we're in LocalStack environment using hardcoded users
            if is_localstack_environment() and session['access_token'].startswith('fake_token_'):
                # For hardcoded users, return a default profile image or None
                return None
            
            access_token = session['access_token']
            
            user_response = cognito.get_user(AccessToken=access_token)
            user_attributes = {attr['Name']: attr['Value'] for attr in user_response['UserAttributes']}
            
            if 'custom:profile_image' in user_attributes:
                s3 = get_s3_client()
                bucket_name = os.getenv('S3_BUCKET_NAME', 'tooltrack-profilepic')
                profile_key = user_attributes['custom:profile_image']
                
                profile_image_url = s3.generate_presigned_url('get_object',
                    Params={'Bucket': bucket_name, 'Key': profile_key},
                    ExpiresIn=3600
                )
        except Exception as e:
            print(f"Error getting profile image: {e}")
    
    return profile_image_url

# เพิ่มฟังก์ชันนี้ไว้บริเวณด้านบนของไฟล์
def compress_image(image_file, max_size=(800, 800), quality=85):
    """
    บีบอัดรูปภาพให้มีขนาดและคุณภาพเหมาะสมสำหรับแสดงบนเว็บไซต์
    
    Args:
        image_file: ไฟล์รูปภาพหรือ path ของไฟล์
        max_size: ขนาดสูงสุด (กว้าง, สูง)
        quality: คุณภาพในการบีบอัด (1-100)
        
    Returns:
        BytesIO object ที่มีข้อมูลรูปภาพที่บีบอัดแล้ว, content type
    """
    try:
        img = Image.open(image_file)
        
        # แปลงเป็น RGB ถ้าเป็นโหมด RGBA
        if img.mode == 'RGBA':
            img = img.convert('RGB')
        
        # ปรับขนาดรูปภาพโดยรักษาอัตราส่วน
        img.thumbnail(max_size, Image.LANCZOS)
        
        # บันทึกลงในหน่วยความจำ
        buffer = io.BytesIO()
        
        # ดึงนามสกุลไฟล์
        if hasattr(image_file, 'filename'):
            filename = image_file.filename
        else:
            filename = image_file if isinstance(image_file, str) else "image.jpg"
            
        file_extension = os.path.splitext(filename)[1].lower()
        
        # กำหนด content_type ตามนามสกุลไฟล์
        content_type = 'image/jpeg'
        if file_extension == '.png':
            img.save(buffer, 'PNG', optimize=True)
            content_type = 'image/png'
        elif file_extension == '.gif':
            img.save(buffer, 'GIF')
            content_type = 'image/gif'
        else:
            img.save(buffer, 'JPEG', quality=quality, optimize=True)
            content_type = 'image/jpeg'
        
        # ย้อนกลับไปที่จุดเริ่มต้นของ buffer
        buffer.seek(0)
        
        return buffer, content_type
    
    except Exception as e:
        print(f"Error compressing image: {e}")
        return None, None
@app.route('/', endpoint='main')
def main_page():
    # ตัวแปรสำหรับรูปโปรไฟล์
    profile_image_url = get_profile_image_url()
    
    return render_template('home.html', profile_image_url=profile_image_url)

@app.route('/home', endpoint='home')
def home_page():
    return redirect(url_for('main'))

@app.route('/equipment', endpoint='equipment')
def equipment_page():
    if 'username' not in session:
        flash('Please log in first', 'info')
        print("Login")
        return redirect(url_for('login'))
    profile_image_url = get_profile_image_url()
    return render_template('equipment.html', profile_image_url=profile_image_url)

@app.route('/update_profile_image', methods=['POST'])
def update_profile_image():
    try:
        # ตรวจสอบว่า user login แล้วหรือไม่
        if 'username' not in session or 'access_token' not in session:
            return jsonify({'success': False, 'message': 'Not logged in'}), 401
        
        # ตรวจสอบว่ามีไฟล์ที่อัปโหลดมาหรือไม่
        if 'profile_image' not in request.files:
            return jsonify({'success': False, 'message': 'No file uploaded'}), 400
        
        file = request.files['profile_image']
        
        # ตรวจสอบว่าไฟล์มีชื่อหรือไม่
        if file.filename == '':
            return jsonify({'success': False, 'message': 'No selected file'}), 400
        
        # ตรวจสอบประเภทไฟล์
        if not file.filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
            return jsonify({'success': False, 'message': 'File must be an image (PNG, JPG, JPEG, GIF)'}), 400
        
        # บีบอัดรูปภาพ
        compressed_img, content_type = compress_image(
            file,
            max_size=(400, 400),
            quality=85
        )
        
        if not compressed_img:
            return jsonify({'success': False, 'message': 'Failed to compress image'}), 500
        
        # เตรียมข้อมูลสำหรับการอัปโหลดไปยัง S3
        s3 = get_s3_client()
        bucket_name = os.getenv('S3_BUCKET_NAME', 'tooltrack-profilepic')
        
        # สร้างชื่อไฟล์แบบไม่ซ้ำกัน
        username = session['username']
        file_extension = os.path.splitext(file.filename)[1].lower()
        unique_filename = f"{uuid.uuid4()}{file_extension}"
        profile_key = f"profile-images/{username}/{unique_filename}"
        
        try:
            # อัปโหลดไปยัง S3
            s3.upload_fileobj(
                compressed_img,
                bucket_name,
                profile_key,
                ExtraArgs={
                    'ContentType': content_type
                }
            )
            
            # อัพเดตข้อมูลใน Cognito
            cognito.admin_update_user_attributes(
                UserPoolId=USER_POOL_ID,
                Username=username,
                UserAttributes=[
                    {'Name': 'custom:profile_image', 'Value': profile_key}
                ]
            )
            
            # สร้าง URL สำหรับรูปโปรไฟล์ใหม่
            profile_image_url = s3.generate_presigned_url('get_object',
                Params={'Bucket': bucket_name, 'Key': profile_key},
                ExpiresIn=3600  # URL หมดอายุใน 1 ชั่วโมง
            )
            
            return jsonify({
                'success': True,
                'message': 'Profile image updated successfully',
                'image_url': profile_image_url
            })
            
        except Exception as e:
            print(f"Error uploading to S3: {e}")
            return jsonify({'success': False, 'message': f'Failed to upload image: {str(e)}'}), 500
            
    except Exception as e:
        print(f"Error updating profile image: {e}")
        return jsonify({'success': False, 'message': f'Failed to update profile image: {str(e)}'}), 500
@app.route('/profile', endpoint='profile')
def profile_page():
    try:
        # First validate the token
        if not validate_token():
            flash('Your session has expired. Please log in again.', 'info')
            return redirect(url_for('login'))
        username = session.get('username')
        access_token = session.get('access_token')
        if not username or not access_token:
            flash('You need to log in first.', 'error')
            return redirect(url_for('login'))

        # Handle different authentication methods
        if is_localstack_environment() and access_token.startswith('fake_token_'):
            # For hardcoded users in LocalStack
            user_data = session.get('user_data', {})
            
            # Use hardcoded user data
            user_info = {
                'username': username,
                'email': user_data.get('email'),
                'fullname': user_data.get('name'),
                'phone': user_data.get('phone'),
                'faculty': user_data.get('faculty'),
                'student_id': user_data.get('student_id'),
                'club_member': user_data.get('club_member'),
                'dob': user_data.get('dob'),
                'profile_image': url_for('static', filename='images/profile.png')  # Default image
            }
            
            # Check role for hardcoded users
            role = user_data.get('role')
        else:
            # For real Cognito users
            # สร้าง S3 client
            s3 = get_s3_client()
            bucket_name = os.getenv('S3_BUCKET_NAME', 'tooltrack-profilepic')

            # ดึงข้อมูลผู้ใช้จาก Cognito
            response = cognito.get_user(AccessToken=access_token)
            user_attributes = {attr['Name']: attr['Value'] for attr in response['UserAttributes']}
            
            # สร้าง presigned URL สำหรับรูปโปรไฟล์
            profile_image_url = None
            try:
                # ตรวจสอบว่ามี custom attribute สำหรับรูปโปรไฟล์หรือไม่
                if 'custom:profile_image' in user_attributes:
                    profile_key = user_attributes['custom:profile_image']
                    profile_image_url = s3.generate_presigned_url('get_object',
                        Params={'Bucket': bucket_name, 'Key': profile_key},
                        ExpiresIn=3600  # URL หมดอายุใน 1 ชั่วโมง
                    )
            except Exception as e:
                print(f"Error getting profile image: {e}")
            
            # ถ้าไม่มีรูป ให้ใช้รูปเริ่มต้น
            if not profile_image_url:
                profile_image_url = url_for('static', filename='images/profile.png')

            user_info = {
                'username': username,
                'email': user_attributes.get('email'),
                'fullname': user_attributes.get('name'),
                'phone': user_attributes.get('phone_number'),
                'faculty': user_attributes.get('custom:faculty'),
                'student_id': user_attributes.get('custom:student_id'),
                'club_member': user_attributes.get('custom:club_member'),
                'dob': user_attributes.get('custom:dob'),
                'profile_image': profile_image_url
            }
            
            # Get role from Cognito attributes
            role = user_attributes.get('custom:role')

        # ตรวจสอบว่าเป็นแอดมินหรือไม่
        if role == 'admin':
            return render_template('admin_req.html', user_info=user_info)
        else:
            return render_template('profile.html', user_info=user_info , profile_image_url=profile_image_url)

    except ClientError as e:
        error_message = e.response['Error']['Message']
        print(f"Error: {error_message}")
        flash(error_message, 'error')
        return redirect(url_for('login'))
    
@app.route('/login', methods=['GET', 'POST'])
def login():
# Check if user is already logged in with a valid token
    if 'username' in session and 'access_token' in session:
        if validate_token():
            return redirect(url_for('profile'))
        else:
            # Token is invalid, so we clear the session
            # (validate_token already did this)
            pass
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check if we're in LocalStack environment and use hardcoded users
        if is_localstack_environment():
            hardcoded_users = get_hardcoded_users()
            
            if username in hardcoded_users and hardcoded_users[username]['password'] == password:
                # Hardcoded login success
                user_data = hardcoded_users[username]
                
                # Set session data
                session['username'] = username
                session['access_token'] = f'fake_token_{username}_{int(datetime.now().timestamp())}'
                session['user_data'] = user_data
                
                # Check role and redirect accordingly
                if user_data['role'] == 'admin':
                    flash('Login successful as admin! (LocalStack Mode)', 'success')
                    return redirect(url_for('admin_req'))
                else:
                    flash('Login successful! (LocalStack Mode)', 'success')
                    return redirect(url_for('home'))
            else:
                flash('Invalid username or password', 'error')
                return redirect(url_for('login'))
        
        # Original Cognito authentication for real AWS
        secret_hash = get_secret_hash(username, APP_CLIENT_ID, CLIENT_SECRET)

        try:
            # เรียกใช้งาน Cognito เพื่อเข้าสู่ระบบ
            response = cognito.initiate_auth(
                AuthFlow='USER_PASSWORD_AUTH',
                AuthParameters={
                    'USERNAME': username,
                    'PASSWORD': password,
                    'SECRET_HASH': secret_hash
                },
                ClientId=APP_CLIENT_ID
            )

            # ตรวจสอบว่ามี ChallengeName หรือไม่
            if 'ChallengeName' in response and response['ChallengeName'] == 'NEW_PASSWORD_REQUIRED':
                session['username'] = username
                session['session'] = response['Session']
                flash('You need to change your password.', 'info')
                return redirect(url_for('change_password'))
            
            # ถ้าสำเร็จ ให้เก็บ Access Token หรือดำเนินการต่อ
            access_token = response['AuthenticationResult']['AccessToken']
            session['username'] = username
            session['access_token'] = access_token

            # ดึงข้อมูลผู้ใช้จาก Cognito
            user_response = cognito.get_user(
                AccessToken=access_token
            )
            user_attributes = {attr['Name']: attr['Value'] for attr in user_response['UserAttributes']}
            role = user_attributes.get('custom:role')

            # ตรวจสอบว่าเป็นแอดมินหรือไม่
            if role == 'admin':
                flash('Login successful as admin!', 'success')
                return redirect(url_for('admin_req'))
            else:
                flash('Login successful!', 'success')
                return redirect(url_for('profile'))

        except ClientError as e:
            error_message = e.response['Error']['Message']
            print(f"Error: {error_message}")
            flash(error_message, 'error')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'username' not in session or 'session' not in session:
        flash('You need to log in first.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form['new_password']
        username = session['username']

        secret_hash = get_secret_hash(username, APP_CLIENT_ID, CLIENT_SECRET)

        try:
            # เรียกใช้งาน Cognito เพื่อเปลี่ยนรหัสผ่าน
            response = cognito.respond_to_auth_challenge(
                ClientId=APP_CLIENT_ID,
                ChallengeName='NEW_PASSWORD_REQUIRED',
                Session=session['session'],
                ChallengeResponses={
                    'USERNAME': session['username'],
                    'NEW_PASSWORD': new_password,
                    'SECRET_HASH': secret_hash
                }
            )

            # ถ้าสำเร็จ ให้เก็บ Access Token หรือดำเนินการต่อ
            access_token = response['AuthenticationResult']['AccessToken']
            session.clear()  # ล้างข้อมูลใน session
            flash('Password changed successfully!', 'success')
            return redirect(url_for('login'))

        except ClientError as e:
            error_message = e.response['Error']['Message']
            print(f"Error: {error_message}")
            flash(error_message, 'error')
            return redirect(url_for('change_password'))

    return render_template('change_password.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # รับข้อมูลจาก Form
        fullname = request.form['fullname']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm-password']
        faculty = request.form['faculty']
        student_id = request.form['student-id']
        phone = request.form['phone']
        club_member = request.form['club-member']
        dob = request.form['dob']
        
        # รับไฟล์รูปภาพแต่ยังไม่อัปโหลด - เก็บไว้ใน session ชั่วคราว
        profile_pic = request.files.get('profile-pic')

        # ตรวจสอบรหัสผ่าน
        if password != confirm_password:
            return "Passwords do not match!", 400
        secret_hash = get_secret_hash(username, APP_CLIENT_ID, CLIENT_SECRET)
        
        # สร้างผู้ใช้ใน Cognito
        try:
            response = cognito.sign_up(
                ClientId=APP_CLIENT_ID,
                Username=username,
                Password=password,
                SecretHash=secret_hash,
                UserAttributes=[
                    {'Name': 'email', 'Value': email},
                    {'Name': 'name', 'Value': fullname},
                    {'Name': 'phone_number', 'Value': phone},
                    {'Name': 'custom:faculty', 'Value': faculty},
                    {'Name': 'custom:student_id', 'Value': student_id},
                    {'Name': 'custom:club_member', 'Value': club_member},
                    {'Name': 'custom:dob', 'Value': dob},
                    {'Name': 'custom:role', 'Value': 'user'}
                ]
            )
            
            # เตรียมข้อมูลรูปภาพสำหรับการอัปโหลดภายหลัง (หลังจากยืนยัน OTP)
            if profile_pic and profile_pic.filename:
                # ตรวจสอบว่าเป็นไฟล์รูปภาพหรือไม่
                if not profile_pic.filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
                    return jsonify({'status': 'error', 'message': 'File must be an image (PNG, JPG, JPEG, GIF)'})
                
                # บันทึกไฟล์ชั่วคราวใน server
                temp_dir = os.path.join(os.getcwd(), 'temp_uploads')
                os.makedirs(temp_dir, exist_ok=True)
                
                # สร้างชื่อไฟล์ชั่วคราวที่ไม่ซ้ำกัน
                file_extension = os.path.splitext(profile_pic.filename)[1].lower()
                temp_filename = f"{uuid.uuid4()}{file_extension}"
                temp_filepath = os.path.join(temp_dir, temp_filename)
                
                # บันทึกไฟล์ชั่วคราว
                profile_pic.save(temp_filepath)
                
                # เก็บข้อมูลเกี่ยวกับไฟล์ไว้ใน session
                session['temp_profile_pic'] = {
                    'path': temp_filepath,
                    'content_type': profile_pic.content_type,
                    'original_filename': profile_pic.filename
                }
            
            # เก็บ username ไว้ใน session เพื่อใช้ในการยืนยัน
            session['temp_username'] = username
            # ส่งการแจ้งเตือนเพื่อขอรหัส OTP ผ่าน SweetAlert
            return jsonify({'status': 'success', 'message': 'Please enter verification code sent to your email'})
        except ClientError as e:
            error_message = e.response['Error']['Message']
            print(f"Error: {error_message}")
            return jsonify({'status': 'error', 'message': error_message})
    return render_template('signup.html')
  

@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    try:
        data = request.get_json()
        verification_code = data.get('code')
        username = session.get('temp_username')

        if not username:
            return jsonify({'status': 'error', 'message': 'Session expired. Please sign up again.'})

        secret_hash = get_secret_hash(username, APP_CLIENT_ID, CLIENT_SECRET)
        
        # ยืนยันการลงทะเบียน
        cognito.confirm_sign_up(
            ClientId=APP_CLIENT_ID,
            Username=username,
            ConfirmationCode=verification_code,
            SecretHash=secret_hash
        )
        
        # หลังจากยืนยัน OTP สำเร็จ ตรวจสอบว่ามีการเตรียมรูปโปรไฟล์ไว้หรือไม่
        profile_image_key = None
        temp_profile_pic = session.get('temp_profile_pic')
        
        if temp_profile_pic:
            try:
                # สร้าง S3 client
                s3 = get_s3_client()
                bucket_name = os.getenv('S3_BUCKET_NAME', 'tooltrack-profilepic')
                
                # บีบอัดรูปภาพ
                compressed_img, content_type = compress_image(
                    temp_profile_pic['path'],
                    max_size=(400, 400),  # ขนาดเหมาะสมสำหรับรูปโปรไฟล์
                    quality=85
                )
                
                if compressed_img:
                    # เตรียมข้อมูลสำหรับการอัปโหลด
                    file_extension = os.path.splitext(temp_profile_pic['original_filename'])[1].lower()
                    unique_filename = f"{uuid.uuid4()}{file_extension}"
                    profile_image_key = f"profile-images/{username}/{unique_filename}"
                    
                    # อัปโหลดไฟล์ที่บีบอัดแล้วไปยัง S3
                    s3.upload_fileobj(
                        compressed_img,
                        bucket_name,
                        profile_image_key,
                        ExtraArgs={
                            'ContentType': content_type
                        }
                    )
                
                    # อัพเดต user attributes ใน Cognito
                    cognito.admin_update_user_attributes(
                        UserPoolId=USER_POOL_ID,
                        Username=username,
                        UserAttributes=[
                            {'Name': 'custom:profile_image', 'Value': profile_image_key}
                        ]
                    )
                
                # ลบไฟล์ชั่วคราวหลังจากอัปโหลดเสร็จ
                os.remove(temp_profile_pic['path'])
                
            except Exception as e:
                print(f"Error uploading profile image: {e}")
        
        # ลบข้อมูลชั่วคราวจาก session
        session.pop('temp_username', None)
        session.pop('temp_profile_pic', None)
        
        return jsonify({'status': 'success', 'message': 'Your account has been verified successfully!'})
    except ClientError as e:
        error_message = e.response['Error']['Message']
        print(f"Error: {error_message}")
        return jsonify({'status': 'error', 'message': error_message})
@app.route('/resend-otp', methods=['POST'])
def resend_otp():
    try:
        username = session.get('temp_username')
        
        if not username:
            return jsonify({'status': 'error', 'message': 'Session expired. Please sign up again.'})
            
        secret_hash = get_secret_hash(username, APP_CLIENT_ID, CLIENT_SECRET)
        
        # เรียกใช้ API เพื่อส่งรหัสยืนยันใหม่
        cognito.resend_confirmation_code(
            ClientId=APP_CLIENT_ID,
            Username=username,
            SecretHash=secret_hash
        )
        
        return jsonify({'status': 'success', 'message': 'Verification code has been resent to your email'})
    except ClientError as e:
        error_message = e.response['Error']['Message']
        print(f"Error: {error_message}")
        return jsonify({'status': 'error', 'message': error_message})
    
@app.route('/signup-success')
def signup_success():
    return "Signup successful! Please verify your email."

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# @app.route('/details_camera')
# def details_camera():
#     try:
#         response = EquipmentTable.scan(
#             FilterExpression=Attr('Category').eq('Cameras')
#         )
#         items = response['Items']
#         # ตรวจสอบว่ามีฟิลด์ isMemberRequired หรือไม่
#         for item in items:
#             item['isMemberRequired'] = item.get('isMemberRequired', 'no')  # ค่าเริ่มต้นเป็น 'no' ถ้าไม่มีฟิลด์นี้
#         return render_template('detailscamera.html', items=items)
#     except Exception as e:
#         print(f"Error: {e}")
#         return "An error occurred while fetching data from DynamoDB."
def has_overdue_items(user_id):
    """
    ตรวจสอบว่าผู้ใช้มีรายการยืมที่เกินกำหนดคืนหรือไม่
    
    Args:
        user_id: รหัสผู้ใช้ที่ต้องการตรวจสอบ
        
    Returns:
        bool: True หากมีรายการเกินกำหนด, False หากไม่มี
    """
    try:
        # ดึงรายการยืมทั้งหมดของผู้ใช้ที่มีสถานะ Approved และ RequestType เป็น borrow
        response = BorrowReturnRecordsTable.scan(
            FilterExpression=
                Attr('user_id').eq(user_id) & 
                Attr('RequestType').eq('borrow') & 
                Attr('StatusReq').eq('Approved') &
                Attr('isApprovedYet').eq('true')
        )
        
        if 'Items' not in response:
            return False
            
        records = response['Items']
        
        # ดึงวันที่ปัจจุบัน
        local_tz = pytz.timezone('Asia/Bangkok')
        now = datetime.now(local_tz)
        
        for record in records:
            # ตรวจสอบว่ามี record ที่ยังไม่มีการคืนและเลยกำหนดแล้ว
            item_id = record.get('item_id')
            if not item_id:
                continue
                
            due_date_str = record.get('due_date')
            if due_date_str == '-':  # หากไม่มีวันครบกำหนด
                continue
                
            try:
                due_date = datetime.strptime(due_date_str, '%Y-%m-%d %H:%M:%S')
                due_date = local_tz.localize(due_date)  # เพิ่ม timezone
                
                # ตรวจสอบว่าเลยกำหนดหรือยัง
                if now > due_date:
                    # ตรวจสอบว่าได้คืนแล้วหรือไม่
                    return_response = BorrowReturnRecordsTable.scan(
                        FilterExpression=
                            Attr('user_id').eq(user_id) & 
                            Attr('RequestType').eq('return') & 
                            Attr('StatusReq').eq('Approved') &
                            Attr('item_id').eq(item_id)
                    )
                    
                    # ถ้าไม่มีรายการคืนที่ตรงกับ item_id นี้
                    if 'Items' not in return_response or len(return_response['Items']) == 0:
                        return True  # พบรายการที่เกินกำหนดและยังไม่คืน
            except ValueError:
                continue  # กรณีรูปแบบวันที่ไม่ถูกต้อง
                
        return False  # ไม่พบรายการที่เกินกำหนด
        
    except Exception as e:
        print(f"Error checking overdue items: {e}")
        return False  # กรณีเกิดข้อผิดพลาด ให้ถือว่าไม่มีรายการเกินกำหนด (เพื่อไม่ให้ block user โดยไม่จำเป็น)
@app.route('/equipment_detail')
def equipment_detail():
    try:
        # รับค่า category จาก query parameter
        category = request.args.get('category')
        
        if not category:
            flash('Category parameter is required', 'error')
            return redirect(url_for('equipment'))
        
        # ดึงข้อมูลจาก DynamoDB ตาม category ที่ได้รับ
        response = EquipmentTable.scan(
            FilterExpression=Attr('Category').eq(category)
        )
        items = response['Items']
        
        # ตรวจสอบว่ามีฟิลด์ isMemberRequired หรือไม่
        for item in items:
            item['isMemberRequired'] = item.get('isMemberRequired', 'no')  # ค่าเริ่มต้นเป็น 'no' ถ้าไม่มีฟิลด์นี้
        profile_image_url = get_profile_image_url()
        return render_template('equipment_detail.html', items=items, category=category , profile_image_url=profile_image_url)
    except Exception as e:
        print(f"Error: {e}")
        flash('An error occurred while fetching data from DynamoDB.', 'error')
        return redirect(url_for('equipment'))
    
@app.route('/borrow/<equipment_id>', methods=['POST'])
def borrow_equipment(equipment_id):
    try:
        # Step 1: Retrieve the equipment details
        equipment = EquipmentTable.get_item(Key={'EquipmentID': equipment_id})
        if 'Item' not in equipment:
            return jsonify(success=False, message="Equipment not found"), 404

        equipment_item = equipment['Item']
        current_quantity = int(equipment_item.get('Quantity', 0))
        
        if current_quantity <= 0:
            return jsonify(success=False, message="Equipment is not available"), 400

        # Step 2: Check member requirements
        access_token = session.get('access_token')
        if not access_token:
            return jsonify(success=False, message="User not logged in"), 401

        username = session.get('username')
        
        # Handle different authentication methods
        if is_localstack_environment() and access_token.startswith('fake_token_'):
            # For hardcoded users in LocalStack
            user_data = session.get('user_data', {})
            club_member = user_data.get('club_member', 'no')
        else:
            # For real Cognito users
            user_response = cognito.get_user(AccessToken=access_token)
            user_attributes = {attr['Name']: attr['Value'] for attr in user_response['UserAttributes']}
            club_member = user_attributes.get('custom:club_member', 'no')

        is_member_required = equipment_item.get('isMemberRequired', 'no')
        if is_member_required == 'yes' and club_member != 'yes':
            return jsonify(success=False, message="This equipment is restricted to members only"), 403

        # Step 3: Check if user has overdue items
        if has_overdue_items(username):
            return jsonify(success=False, 
                         message="You have overdue items. Please return them before borrowing new equipment"), 403

        # Step 4: Create borrow request record
        local_tz = pytz.timezone('Asia/Bangkok')
        now = datetime.now(local_tz)
        record_id = generate_record_id()
        if not record_id:
            return jsonify(success=False, message="Failed to generate record ID"), 500

        BorrowReturnRecordsTable.put_item(
            Item={
                'record_id': record_id,
                'user_id': username,
                'equipment_id': equipment_id,
                'equipment_name': equipment_item['Name'],
                'RequestType': 'borrow',
                'record_date': now.strftime('%Y-%m-%d %H:%M:%S'),
                'due_date': '-',  # เริ่มต้นเป็น '-'
                'StatusReq': 'Pending',
                'isApprovedYet': 'false'
            }
        )
        return jsonify(success=True, message="Borrow request submitted successfully")

    except Exception as e:
        print(f"Error: {e}")
        return jsonify(success=False, message="An unexpected error occurred"), 500
    # @app.route('/details_lenses')
# def details_lenses():
#     try:
#         response = EquipmentTable.scan(
#             FilterExpression=Attr('Category').eq('Lenses')
#         )
#         items = response['Items']
#         # เพิ่ม isMemberRequired ถ้าไม่มี
#         for item in items:
#             item['isMemberRequired'] = item.get('isMemberRequired', 'no')
#         return render_template('detailslenses.html', items=items)
#     except Exception as e:
#         print(f"Error: {e}")
#         return "An error occurred while fetching data from DynamoDB."

# @app.route('/details_accessories')
# def details_accessories():
#     try:
#         response = EquipmentTable.scan(
#             FilterExpression=Attr('Category').eq('Accessories')
#         )
#         items = response['Items']
#         # เพิ่ม isMemberRequired ถ้าไม่มี
#         for item in items:
#             item['isMemberRequired'] = item.get('isMemberRequired', 'no')
#         return render_template('detailsaccessories.html', items=items)
#     except Exception as e:
#         print(f"Error: {e}")
#         return "An error occurred while fetching data from DynamoDB."

@app.route('/list', endpoint='list')
def list_records():
    try:
        user_id = session.get('username')
        if not user_id:
            flash('You need to log in first.', 'info')
            return redirect(url_for('login'))

        response = BorrowReturnRecordsTable.scan(
            FilterExpression=Attr('user_id').eq(user_id)
        )
        records = response['Items']
        
        # เรียงลำดับตามวันที่และเวลาล่าสุด
        records.sort(key=lambda x: x['record_date'], reverse=True)
        profile_image_url = get_profile_image_url()
        return render_template('list.html', records=records , profile_image_url=profile_image_url)
    except Exception as e:
        print(f"Error: {e}")
        return "An error occurred while fetching data from DynamoDB."
    return render_template('list.html')

@app.route('/return', methods=['POST'])
def return_item():
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['user_id', 'equipment_id', 'equipment_name', 'due_date', 'item_id']
        for field in required_fields:
            if field not in data:
                return jsonify({
                    'success': False,
                    'message': f'Missing required field: {field}'
                }), 400

        local_tz = pytz.timezone('Asia/Bangkok')
        now = datetime.now(local_tz)
        record_id = generate_record_id()
        
        if not record_id:
            return jsonify({
                'success': False,
                'message': 'Failed to generate record ID'
            }), 500
        
        # Create return record with item_id
        BorrowReturnRecordsTable.put_item(
            Item={
                'record_id': record_id,
                'user_id': data['user_id'],
                'equipment_id': data['equipment_id'],
                'equipment_name': data['equipment_name'],
                'RequestType': 'return',
                'record_date': now.strftime('%Y-%m-%d %H:%M:%S'),
                'due_date': data['due_date'],
                'StatusReq': 'Pending',
                'isApprovedYet': 'false',
                'item_id': data['item_id']  # Store the item_id
            }
        )
        
        return jsonify({
            'success': True,
            'message': 'Return request submitted successfully'
        })

    except Exception as e:
        print(f"Error in return_item: {e}")
        return jsonify({
            'success': False,
            'message': f'Failed to submit return request: {str(e)}'
        }), 500

@app.route('/admin_req')
def admin_req():
    try:
        user_id = session.get('username')
        if not user_id:
            flash('You need to log in first.', 'info')
            return redirect(url_for('login'))

        response = BorrowReturnRecordsTable.scan(
            FilterExpression=Attr('StatusReq').eq('Pending')
        )
        
        if 'Items' in response:
            records = response['Items']
            records.sort(key=lambda x: x['record_date'], reverse=True)
        else:
            records = []

        return render_template('admin_req.html', records=records)
    
    except Exception as e:
        print(f"Error in admin_req: {e}")
        flash('Failed to load requests.', 'error')
        return redirect(url_for('admin_equipment'))

@app.route('/approve/<reqType>/<equipment_name>/<equipment_id>/<user_id>/<record_id>', methods=['POST'])
def approve_record(reqType, equipment_name, equipment_id, user_id, record_id):
    try:
        local_tz = pytz.timezone('Asia/Bangkok')
        now = datetime.now(local_tz)
        borrow_date = now.strftime('%Y-%m-%d %H:%M:%S')
        due_date = (now + timedelta(days=7)).strftime('%Y-%m-%d %H:%M:%S')

        # ดึงข้อมูล Equipment
        equipment = EquipmentTable.get_item(Key={'EquipmentID': equipment_id})
        if 'Item' not in equipment:
            return jsonify(success=False, message="Equipment not found"), 404

        items = equipment['Item'].get('Items', [])
        
        if reqType == 'borrow':
            # หา available item สำหรับการยืม
            available_item = None
            for item in items:
                if item['Status'] == 'Available':
                    available_item = item
                    break
            
            if not available_item:
                return jsonify(success=False, message="No available items"), 400

            # อัพเดตสถานะของ item ที่ถูกยืม
            for item in items:
                if item['ItemID'] == available_item['ItemID']:
                    item['Status'] = 'Not Available'
                    item['BorrowerID'] = user_id
                    item['BorrowDate'] = borrow_date
                    item['DueDate'] = due_date
                    break

            # นับจำนวน items ที่ยังคงมีสถานะ Available
            available_count = sum(1 for item in items if item['Status'] == 'Available')

            # อัพเดต Equipment table
            EquipmentTable.update_item(
                Key={'EquipmentID': equipment_id},
                UpdateExpression="SET #items = :items, Quantity = :qty, StatusEquipment = :status",
                ExpressionAttributeNames={
                    '#items': 'Items'
                },
                ExpressionAttributeValues={
                    ':items': items,
                    ':qty': available_count,
                    ':status': 'Available' if available_count > 0 else 'Not Available'
                }
            )

            # อัพเดต BorrowReturnRecords และเพิ่ม due_date
            BorrowReturnRecordsTable.update_item(
                Key={'record_id': record_id},
                UpdateExpression="SET StatusReq = :s, isApprovedYet = :a, item_id = :iid, due_date = :dd",
                ExpressionAttributeValues={
                    ':s': 'Approved',
                    ':a': 'true',
                    ':iid': available_item['ItemID'],
                    ':dd': (now + timedelta(days=7)).strftime('%Y-%m-%d %H:%M:%S')  # กำหนด due_date ตอน approve
                }
            )

        elif reqType == 'return':
            # ดึงข้อมูล item_id จาก record
            record = BorrowReturnRecordsTable.get_item(Key={'record_id': record_id})
            if 'Item' not in record:
                return jsonify(success=False, message="Record not found"), 404
            
            return_item_id = record['Item'].get('item_id')
            if not return_item_id:
                return jsonify(success=False, message="Item ID not found in record"), 400

            # เพิ่มวันที่ return ในปัจจุบัน
            local_tz = pytz.timezone('Asia/Bangkok')
            now = datetime.now(local_tz)
            return_date = now.strftime('%Y-%m-%d %H:%M:%S')

            # หา item ที่จะคืนและอัพเดตสถานะ
            item_updated = False
            for item in items:
                if item['ItemID'] == return_item_id:
                    item['Status'] = 'Available'
                    item['BorrowerID'] = '-'
                    item['BorrowDate'] = '-'
                    item['DueDate'] = '-'
                    item_updated = True
                    break
            
            if not item_updated:
                return jsonify(success=False, message="Item not found in equipment"), 404

            # อัพเดต Equipment table
            EquipmentTable.update_item(
                Key={'EquipmentID': equipment_id},
                UpdateExpression="SET #items = :items",
                ExpressionAttributeNames={
                    '#items': 'Items'
                },
                ExpressionAttributeValues={
                    ':items': items
                }
            )

# นับจำนวน items ที่ยังคงมีสถานะ Available
            available_count = sum(1 for item in items if item['Status'] == 'Available')

            # อัพเดต Quantity และ StatusEquipment
            EquipmentTable.update_item(
                Key={'EquipmentID': equipment_id},
                UpdateExpression="SET Quantity = :qty, StatusEquipment = :status",
                ExpressionAttributeValues={
                    ':qty': available_count,
                    ':status': 'Available' if available_count > 0 else 'Not Available'
                }
            )

            # อัพเดต BorrowReturnRecordsTable
            BorrowReturnRecordsTable.update_item(
                Key={'record_id': record_id},
                UpdateExpression="SET StatusReq = :s, isApprovedYet = :a, return_date = :rd",
                ExpressionAttributeValues={
                    ':s': 'Approved',
                    ':a': 'true',
                    ':rd': return_date
                }
            )

        return jsonify(success=True, message="Request approved successfully")

    except Exception as e:
        print(f"Error in approve_record: {e}")
        return jsonify(success=False, message=str(e)), 500

@app.route('/admin_list')
def admin_list():
    try:
        user_id = session.get('username')
        if not user_id:
            flash('You need to log in first.', 'info')
            return redirect(url_for('login'))

        response = BorrowReturnRecordsTable.scan()
        records = response['Items']
        
        # เรียงลำดับตามวันที่และเวลาล่าสุด
        records.sort(key=lambda x: x['record_date'], reverse=True)
        
        return render_template('admin_list.html', records=records)
    except Exception as e:
        print(f"Error: {e}")
        return "An error occurred while fetching data from DynamoDB."
    return render_template('admin_req.html')

@app.route('/admin_lenses')
def admin_lenses():
    try:
        response = EquipmentTable.scan(
            FilterExpression=Attr('Category').eq('Lenses')
        )
        items = response['Items']
        return render_template('admin_lenses.html', items=items)
    except Exception as e:
        print(f"Error: {e}")
        return "An error occurred while fetching data from DynamoDB."

@app.route('/admin_equipdetail')
def admin_equipdetail():
    try:
        category = request.args.get('category')
        
        if not category:
            flash('Category parameter is required', 'error')
            return redirect(url_for('equipment'))
        
        response = EquipmentTable.scan(
            FilterExpression=Attr('Category').eq(category)
        )
        items = response['Items']
        return render_template('admin_equipdetail.html', items=items, category=category)
    except Exception as e:
        print(f"Error: {e}")
        return "An error occurred while fetching data from DynamoDB."

@app.route('/admin_equipment')
def admin_equipment():
    try:
        user_id = session.get('username')
        if not user_id:
            flash('You need to log in first.', 'info')
            return redirect(url_for('login'))
        # ดึงข้อมูลอุปกรณ์ทั้งหมดจาก DynamoDB
        response = EquipmentTable.scan()
        items = response['Items']
        return render_template('admin_equipment.html', items=items)
    except Exception as e:
        print(f"Error: {e}")
        return "An error occurred while fetching data from DynamoDB."

@app.route('/admin_accessories')
def admin_accessories():
    try:
        response = EquipmentTable.scan(
            FilterExpression=Attr('Category').eq('Accessories')
        )
        items = response['Items']
        return render_template('admin_accessories.html', items=items)
    except Exception as e:
        print(f"Error: {e}")
        return "An error occurred while fetching data from DynamoDB."

@app.route('/admin_camera')
def admin_camera():
    try:
        # ดึงข้อมูลจาก DynamoDB
        response = EquipmentTable.scan(
            FilterExpression=Attr('Category').eq('Cameras')
        )
        items = response['Items']
        return render_template('admin_camera.html', items=items)
    except Exception as e:
        print(f"Error: {e}")
        return "An error occurred while fetching data from DynamoDB."

def generate_item_ids(equipment_id, start_number, quantity):
    """สร้าง ItemID สำหรับแต่ละชิ้นของอุปกรณ์"""
    try:
        item_ids = []
        for i in range(quantity):
            item_id = f"{equipment_id}-{(start_number + i):03d}"
            item_ids.append({
                'ItemID': item_id,
                'Status': 'Available',
                'BorrowerID': '-',
                'BorrowDate': '-',
                'DueDate': '-'
            })
        return item_ids
    except Exception as e:
        print(f"Error generating item IDs: {e}")
        return None

@app.route('/admin_add_equipment', methods=['GET', 'POST'])
def admin_add_equipment():
    if request.method == 'POST':
        try:
            name = request.form.get('name')
            category = request.form.get('category')
            isMemberRequired = request.form.get('isMemberRequired')
            quantity = int(request.form.get('quantity'))

            if not name or not category or not isMemberRequired or not quantity:
                return jsonify({
                    'success': False,
                    'message': 'All fields are required.'
                })

            # Extract serial numbers for each equipment unit
            serials = []
            for i in range(1, quantity + 1):
                serial = request.form.get(f'serial_number_{i}')
                if not serial:
                    return jsonify({
                        'success': False,
                        'message': f'Missing serial number for item {i}.'
                    })
                serials.append(serial)

            # ตรวจสอบว่ามีอุปกรณ์ชื่อนี้อยู่แล้วหรือไม่
            response = EquipmentTable.scan(
                FilterExpression=Attr('Name').eq(name) & Attr('Category').eq(category)
            )
            items = response['Items']

            if items:
                # ถ้ามีอุปกรณ์อยู่แล้ว ใช้ EquipmentID เดิม
                existing_item = items[0]
                equipment_id = existing_item['EquipmentID']
                current_quantity = int(existing_item.get('Quantity', 0))
                existing_items = existing_item.get('Items', [])
                
                # หาเลขลำดับ ItemID ล่าสุด
                max_item_number = 0
                for item in existing_items:
                    item_number = int(item['ItemID'].split('-')[-1])
                    max_item_number = max(max_item_number, item_number)
                
                # สร้าง ItemID ใหม่ต่อจากเลขเดิม
                new_items = []
                for i in range(quantity):
                    item_id = f"{equipment_id}-{(max_item_number + i + 1):03d}"
                    new_items.append({
                        'ItemID': item_id,
                        'Status': 'Available',
                        'BorrowerID': '-',
                        'BorrowDate': '-',
                        'DueDate': '-',
                        'SerialNumber': serials[i]  # เพิ่ม serial number
                    })
                
                # รวม items เก่าและใหม่
                all_items = existing_items + new_items
                new_quantity = current_quantity + quantity

                # อัพเดตข้อมูลในตาราง
                EquipmentTable.update_item(
                    Key={'EquipmentID': equipment_id},
                    UpdateExpression='SET #qty = :new_qty, #st = :new_status, #member = :member_req, #items = :items',
                    ExpressionAttributeNames={
                        '#qty': 'Quantity',
                        '#st': 'StatusEquipment',
                        '#member': 'isMemberRequired',
                        '#items': 'Items'
                    },
                    ExpressionAttributeValues={
                        ':new_qty': new_quantity,
                        ':new_status': 'Available',
                        ':member_req': isMemberRequired,
                        ':items': all_items
                    }
                )
            else:
                # ถ้าเป็นอุปกรณ์ใหม่ สร้าง EquipmentID ใหม่
                equipment_id = generate_equipment_id(category)
                if not equipment_id:
                    return jsonify({
                        'success': False,
                        'message': 'Failed to generate equipment ID'
                    })
                
                # สร้าง items พร้อม serial numbers
                items = []
                for i in range(quantity):
                    item_id = f"{equipment_id}-{(i + 1):03d}"
                    items.append({
                        'ItemID': item_id,
                        'Status': 'Available',
                        'BorrowerID': '-',
                        'BorrowDate': '-',
                        'DueDate': '-',
                        'SerialNumber': serials[i]  # เพิ่ม serial number
                    })

                # เพิ่มข้อมูลใหม่
                EquipmentTable.put_item(
                    Item={
                        'EquipmentID': equipment_id,
                        'Name': name,
                        'Category': category,
                        'StatusEquipment': 'Available',
                        'Quantity': quantity,
                        'Items': items,
                        'isMemberRequired': isMemberRequired
                    }
                )

            redirect_url = url_for('admin_equipment')
            
            return jsonify({
                'success': True,
                'message': f'Success! Added {quantity} units of {name}',
                'redirect': redirect_url
            })

        except Exception as e:
            print(f"Error in admin_add_equipment: {e}")
            return jsonify({
                'success': False,
                'message': f'Failed to add equipment: {str(e)}'
            })

    return render_template('admin_add_equipment.html')

def update_equipment_quantity(equipment_id):
    """อัพเดต Quantity ตามจำนวน Items ที่มีสถานะ Available"""
    try:
        equipment = EquipmentTable.get_item(Key={'EquipmentID': equipment_id})
        if 'Item' in equipment:
            items = equipment['Item'].get('Items', [])
            available_count = sum(1 for item in items if item['Status'] == 'Available')
            
            EquipmentTable.update_item(
                Key={'EquipmentID': equipment_id},
                UpdateExpression='SET Quantity = :qty, StatusEquipment = :status',
                ExpressionAttributeValues={
                    ':qty': available_count,
                    ':status': 'Available' if available_count > 0 else 'Not Available'
                }
            )
            return True
    except Exception as e:
        print(f"Error updating equipment quantity: {e}")
        return False

@app.route('/delete_equipment/<equipment_id>', methods=['POST'])
def delete_equipment(equipment_id):
    try:
        equipment = EquipmentTable.get_item(Key={'EquipmentID': equipment_id})
        
        if 'Item' not in equipment:
            return jsonify({
                'success': False,
                'message': 'Equipment not found'
            }), 404

        items = equipment['Item'].get('Items', [])
        available_items = [item for item in items if item['Status'] == 'Available']
        
        if not available_items:
            return jsonify({
                'success': False,
                'message': 'No available items to delete'
            }), 400

        # ลบ item ล่าสุดที่มีสถานะ Available
        item_to_delete = available_items[-1]
        for item in items:
            if item['ItemID'] == item_to_delete['ItemID']:
                item['Status'] = 'Deleted'
                break

        # อัพเดต Items list และ Quantity
        EquipmentTable.update_item(
            Key={'EquipmentID': equipment_id},
            UpdateExpression='SET Items = :items',
            ExpressionAttributeValues={
                ':items': items
            }
        )

        # อัพเดต Quantity ตามจำนวน Items ที่ Available
        if update_equipment_quantity(equipment_id):
            available_count = sum(1 for item in items if item['Status'] == 'Available')
            return jsonify({
                'success': True,
                'message': f'Successfully deleted 1 unit. Remaining: {available_count}'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to update equipment quantity'
            }), 500

    except Exception as e:
        print(f"Error in delete_equipment: {e}")
        return jsonify({
            'success': False,
            'message': f'Failed to delete equipment: {str(e)}'
        }), 500

@app.route('/delete_equipment_item/<equipment_id>/<item_id>', methods=['POST'])
def delete_equipment_item(equipment_id, item_id):
    try:
        equipment = EquipmentTable.get_item(Key={'EquipmentID': equipment_id})
        
        if 'Item' not in equipment:
            return jsonify({
                'success': False,
                'message': 'Equipment not found'
            }), 404

        items = equipment['Item'].get('Items', [])
        found = False
        
        # หา item และลบออกจาก items list
        for i, item in enumerate(items):
            if item['ItemID'] == item_id:
                if item['Status'] != 'Available':
                    return jsonify({
                        'success': False,
                        'message': 'Item is not available for deletion'
                    }), 400
                items.pop(i)  # ลบ item ออกจาก list
                found = True
                break
        
        if not found:
            return jsonify({
                'success': False,
                'message': 'Item not found'
            }), 404

        # อัพเดต Items list ใน DynamoDB
        EquipmentTable.update_item(
            Key={'EquipmentID': equipment_id},
            UpdateExpression='SET #items = :items',
            ExpressionAttributeNames={
                '#items': 'Items'
            },
            ExpressionAttributeValues={
                ':items': items
            }
        )

        # อัพเดต Quantity
        if update_equipment_quantity(equipment_id):
            available_count = len(items)  # นับจำนวน items ที่เหลือ
            return jsonify({
                'success': True,
                'message': f'Successfully deleted item. Remaining: {available_count}'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to update equipment quantity'
            }), 500

    except Exception as e:
        print(f"Error in delete_equipment_item: {e}")
        return jsonify({
            'success': False,
            'message': f'Failed to delete item: {str(e)}'
        }), 500

def generate_record_id():
    try:
        response = BorrowReturnRecordsTable.scan()
        existing_records = response['Items']
        max_id = 0
        for record in existing_records:
            if record['record_id'].startswith('record'):
                current_id = int(record['record_id'][6:])  # ตัด 'record' ออกและแปลงเป็นตัวเลข
                max_id = max(max_id, current_id)
        new_id = f"record{(max_id + 1):03d}"  # เพิ่มเลขถัดไปและจัดรูปแบบให้มี 3 หลัก
        return new_id
    except Exception as e:
        print(f"Error generating record ID: {e}")
        return None

def generate_equipment_id(category):
    try:
        # ลบช่องว่างและแปลงเป็นตัวพิมพ์เล็กทั้งหมด
        category_prefix = category.lower().replace(' ', '')
        
        # ดึงข้อมูลอุปกรณ์ที่มีอยู่ในประเภทเดียวกัน
        response = EquipmentTable.scan(
            FilterExpression=Attr('Category').eq(category)
        )
        existing_items = response['Items']
        max_id = 0
        
        # หาเลขลำดับสูงสุดที่มีอยู่
        for item in existing_items:
            if item['EquipmentID'].startswith(category_prefix):
                try:
                    # แยกเอาเฉพาะตัวเลขท้าย
                    current_id = int(item['EquipmentID'][len(category_prefix):])
                    max_id = max(max_id, current_id)
                except ValueError:
                    continue
        
        # สร้าง ID ใหม่โดยใช้ชื่อประเภทจริง + เลขลำดับ 3 หลัก
        new_id = f"{category_prefix}{(max_id + 1):03d}"
        return new_id
        
    except Exception as e:
        print(f"Error generating equipment ID: {e}")
        return None

@app.route('/get_item_list/<equipment_id>', methods=['GET'])
def get_item_list(equipment_id):
    try:
        equipment = EquipmentTable.get_item(Key={'EquipmentID': equipment_id})
        
        if 'Item' not in equipment:
            return jsonify({
                'success': False,
                'message': 'Equipment not found'
            }), 404

        items = equipment['Item'].get('Items', [])
        equipment_name = equipment['Item'].get('Name', '')
        
        # เรียงลำดับตาม ItemID
        items.sort(key=lambda x: x['ItemID'])
        
        return jsonify({
            'success': True,
            'items': items,
            'equipment_name': equipment_name
        })

    except Exception as e:
        print(f"Error getting item list: {e}")
        return jsonify({
            'success': False,
            'message': 'Failed to get item list'
        }), 500

@app.route('/get_categories', methods=['GET'])
def get_categories():
    try:
        # ดึงข้อมูลทั้งหมดจาก Equipment table
        response = EquipmentTable.scan()
        items = response['Items']
        
        # รวบรวมประเภทที่มีอยู่ทั้งหมด
        categories = set()
        for item in items:
            if 'Category' in item:
                categories.add(item['Category'])
        
        # แปลงเป็น list และเรียงลำดับ
        categories_list = sorted(list(categories))
        
        return jsonify({
            'success': True,
            'categories': categories_list
        })
    except Exception as e:
        print(f"Error getting categories: {e}")
        return jsonify({
            'success': False,
            'message': 'Failed to get categories'
        }), 500

@app.route('/admin_home')
def admin_home():
    try:
        # ตรวจสอบการล็อกอิน
        if 'username' not in session:
            flash('Please log in first', 'info')
            return redirect(url_for('login'))
            
        # ตรวจสอบสิทธิ์ admin
        access_token = session.get('access_token')
        user_response = cognito.get_user(
            AccessToken=access_token
        )
        user_attributes = {attr['Name']: attr['Value'] 
                         for attr in user_response['UserAttributes']}
        
        if user_attributes.get('custom:role') != 'admin':
            flash('You do not have permission to access this page', 'error')
            return redirect(url_for('home'))
            
        return render_template('admin_home.html')
        
    except Exception as e:
        print(f"Error in admin_home: {str(e)}")
        flash('An error occurred', 'error')
        return redirect(url_for('login'))

@app.route('/admin_profile')
def admin_profile():
    try:
        # ตรวจสอบการล็อกอิน
        if 'username' not in session or 'access_token' not in session:
            flash('Please log in first', 'info')
            return redirect(url_for('login'))
            
        # ดึงข้อมูล user จาก Cognito
        access_token = session['access_token']
        user_response = cognito.get_user(
            AccessToken=access_token
        )
        
        # แปลง attributes เป็น dict
        user_attributes = {attr['Name']: attr['Value'] 
                         for attr in user_response['UserAttributes']}
        
        # ตรวจสอบสิทธิ์ admin
        if user_attributes.get('custom:role') != 'admin':
            flash('You do not have permission to access this page', 'error')
            return redirect(url_for('home'))
            
        # สร้าง user_info dictionary
        user_info = {
            'username': session['username'],
            'email': user_attributes.get('email'),
            'fullname': user_attributes.get('name'),
            'phone': user_attributes.get('phone_number'),
            'role': user_attributes.get('custom:role')
        }
            
        return render_template('admin_profile.html', user_info=user_info)
        
    except Exception as e:
        print(f"Error in admin_profile: {str(e)}")
        flash('An error occurred while loading profile', 'error')
        return redirect(url_for('admin_req'))
    
@app.route('/item_history/<equipment_id>/<item_id>')
def item_history(equipment_id, item_id):
    try:
        # Scan หา record ที่มี item_id ตรงกัน
        response = BorrowReturnRecordsTable.scan(
            FilterExpression=Attr('equipment_id').eq(equipment_id) & Attr('item_id').eq(item_id)
        )
        records = response.get('Items', [])
        # เรียงลำดับล่าสุดก่อน
        records.sort(key=lambda x: x.get('record_date', ''), reverse=True)
        # เตรียมข้อมูลสำหรับ frontend
        history = []
        for rec in records:
            history.append({
                'user_id': rec.get('user_id', '-'),
                'record_date': rec.get('record_date', '-'),
                'due_date': rec.get('due_date', '-'),
                'RequestType': rec.get('RequestType', '-'),
                'return_date': rec.get('return_date', '-')
            })
        return jsonify(success=True, history=history)
    except Exception as e:
        print(f"Error in item_history: {e}")
        return jsonify(success=False, message="Failed to get item history")

@app.route('/health')
def health_check():
    """Health check endpoint for Docker"""
    try:
        # Basic health check - just return OK if the app is running
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'environment': 'localstack' if os.getenv('AWS_ENDPOINT_URL') else 'aws'
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500

@app.route('/localstack-info')
def localstack_info():
    """Show LocalStack test users info - only available in LocalStack environment"""
    if not is_localstack_environment():
        return jsonify({
            'error': 'This endpoint is only available in LocalStack environment'
        }), 403
    
    test_users_info = [
        {
            'username': 'testuser',
            'password': 'password',
            'email': 'test@example.com',
            'role': 'user',
            'description': 'Regular user for testing'
        },
        {
            'username': 'admin',
            'password': 'admin', 
            'email': 'admin@example.com',
            'role': 'admin',
            'description': 'Admin user for testing'
        }
    ]
    
    return jsonify({
        'environment': 'LocalStack',
        'mode': 'Hard-coded users (No Cognito)',
        'message': 'These users are hard-coded for easy testing in LocalStack',
        'test_users': test_users_info,
        'login_url': '/login',
        'note': 'Use these credentials to login without registration or OTP',
        'updated_time': '2025-09-04 19:15:00'  # เพิ่ม timestamp เพื่อเช็คว่า file update แล้ว
    })

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug)
