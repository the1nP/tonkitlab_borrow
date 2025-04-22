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

app = Flask(__name__)
def get_secrets():
    secret_name = "equipment-app/config"
    region_name = "us-east-1"
    
    # สร้าง Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )
    
    try:
        # ดึงค่า Secret
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            return json.loads(secret)
    except ClientError as e:
        print(f"Error retrieving secrets: {e}")


# ดึงค่า Secrets
secrets = get_secrets()

# ตั้งค่า Flask secret key
app.secret_key = secrets.get('FLASK_SECRET_KEY')
# AWS Cognito Configuration
USER_POOL_ID = secrets.get('USER_POOL_ID')
APP_CLIENT_ID = secrets.get('APP_CLIENT_ID')
CLIENT_SECRET = secrets.get('CLIENT_SECRET')
cognito = boto3.client('cognito-idp', region_name='us-east-1')

# DynamoDB Configuration
dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
EquipmentTable = dynamodb.Table('Equipment')
BorrowReturnRecordsTable = dynamodb.Table('BorrowReturnRecords')

def get_secret_hash(username, client_id, client_secret):
    message = username + client_id
    dig = hmac.new(
        str(client_secret).encode('utf-8'),
        msg=str(message).encode('utf-8'),
        digestmod=hashlib.sha256
    ).digest()
    return base64.b64encode(dig).decode()

@app.route('/home', endpoint='home')
def main_page():
    return render_template('home.html')

@app.route('/equipment', endpoint='equipment')
def equipment_page():
    if 'username' not in session:
        flash('Please log in first', 'info')
        print("Login")
        return redirect(url_for('login'))
    return render_template('equipment.html')

@app.route('/profile', endpoint='profile')
def profile_page():
    username = session.get('username')
    access_token = session.get('access_token')
    if not username or not access_token:
        flash('You need to log in first.', 'error')
        return redirect(url_for('login'))
    try:
        response = cognito.get_user(
            AccessToken=access_token
        )
        user_attributes = {attr['Name']: attr['Value'] for attr in response['UserAttributes']}
        user_info = {
            'username': username,
            'email': user_attributes.get('email'),
            'fullname': user_attributes.get('name'),
            'phone': user_attributes.get('phone_number'),
            'faculty': user_attributes.get('custom:faculty'),
            'student_id': user_attributes.get('custom:student_id'),
            'club_member': user_attributes.get('custom:club_member'),
            'dob': user_attributes.get('custom:dob')
        }
    except ClientError as e:
        error_message = e.response['Error']['Message']
        print(f"Error: {error_message}")
        flash(error_message, 'error')
        return redirect(url_for('login'))

    return render_template('profile.html', user_info=user_info)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session and 'access_token' in session:
        return redirect(url_for('profile'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
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
            flash('You have successfully signed up!', 'success')
            return redirect(url_for('signup'))
        except ClientError as e:
            error_message = e.response['Error']['Message']
            print(f"Error: {error_message}")
            flash(error_message, 'error')
            return redirect(url_for('signup'))

    return render_template('signup.html')

@app.route('/signup-success')
def signup_success():
    return "Signup successful! Please verify your email."

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/details_camera')
def details_camera():
    response = EquipmentTable.scan(
        FilterExpression=Attr('Category').eq('Camera')
    )
    items = response['Items']
    print(items)
    return render_template('detailscamera.html',items=items)

@app.route('/borrow/<equipment_id>', methods=['POST'])
def borrow_equipment(equipment_id):
    try:
        # Step 1: Retrieve the equipment details
        equipment = EquipmentTable.get_item(Key={'EquipmentID': equipment_id})
        if 'Item' not in equipment:
            return jsonify(success=False, message="Equipment not found"), 404

        equipment_item = equipment['Item']
        equipment_name = equipment_item['Name']  # Get the Name attribute
        print(equipment_item)

        # Step 2: Calculate the new due date (one week from today)
        local_tz = pytz.timezone('Asia/Bangkok')  # Replace with your local timezone
        now = datetime.now(local_tz)
        due_date = (now + timedelta(weeks=1)).strftime('%Y-%m-%d %H:%M:%S')
        # Step 3: Update the equipment status to Pending
        EquipmentTable.update_item(
            Key={'EquipmentID': equipment_id},
            UpdateExpression="set #s = :s",
            ExpressionAttributeNames={'#s': 'Status'},
            ExpressionAttributeValues={':s': 'Pending'},
            ReturnValues="UPDATED_NEW"
        )
        # Step 4: Insert a new record into BorrowReturnRecords
        record_id = str(uuid.uuid4())
        user_id = session.get('username')  # Assuming user_id is stored in session
        record_date = now.strftime('%Y-%m-%d %H:%M:%S')

        BorrowReturnRecordsTable.put_item(
            Item={
                'record_id': record_id,
                'user_id': user_id,
                'equipment_id': equipment_id,
                'equipment_name': equipment_name,
                'type': 'borrow',
                'record_date': record_date,
                'due_date': '-',
                'status': 'pending_borrow',
                'isApprovedYet': 'false'
            }
        )
        return jsonify(success=True)
    except Exception as e:
        print(f"Error: {e}")
        return jsonify(success=False), 500

@app.route('/details_accessories')
def details_accessories():
    response = EquipmentTable.scan(
        FilterExpression=Attr('Category').eq('Accessories')
    )
    items = response['Items']
    print(items)
    return render_template('detailsaccessories.html',items=items)

@app.route('/details_lenses')
def details_lenses():
    return render_template('detailslenses.html')

@app.route('/list', endpoint='list')
def list_records():
    try:
        user_id = session.get('username')  # Assuming user_id is stored in session
        if not user_id:
            flash('You need to log in first.', 'info')
            return redirect(url_for('login'))  # Redirect to login if user is not logged in

        response = BorrowReturnRecordsTable.scan(
            FilterExpression=Attr('user_id').eq(user_id)
        )
        records = response['Items']
        return render_template('list.html', records=records)
    except Exception as e:
        print(f"Error: {e}")
        return "An error occurred while fetching data from DynamoDB."
    return render_template('list.html')

@app.route('/return', methods=['POST'])
def return_item():
    try:
        local_tz = pytz.timezone('Asia/Bangkok')  # Replace with your local timezone
        now = datetime.now(local_tz)
        
        #record_id = request.form['record_id']
        user_id = request.form['user_id']
        equipment_id = request.form['equipment_id']
        equipment_name = request.form['equipment_name']
        record_date = request.form['record_date']
        due_date = request.form['due_date']

        # response = BorrowReturnRecordsTable.scan(
        #     FilterExpression=Attr('equipment_id').eq(equipment_id) & Attr('status').eq('pending_return')
        # )
        # pending_request = response['Items']
        # if pending_request:
        #     flash('There is already a pending return request for this equipment.', 'info')
        #     return redirect(url_for('list'))

        record_id = str(uuid.uuid4())
        user_id = session.get('username')  # Assuming user_id is stored in session
        record_date = now.strftime('%Y-%m-%d %H:%M:%S')
        BorrowReturnRecordsTable.put_item(
            Item={
                'record_id': record_id,
                'user_id': user_id,
                'equipment_id': equipment_id,
                'equipment_name': equipment_name,
                'type': 'return',
                'record_date': record_date,
                'due_date': due_date,
                'status': 'pending_return',
                'isApprovedYet': 'false'
            }
        )
        flash('Return request submitted successfully.', 'success')
        return redirect(url_for('list'))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin_req')
def admin_req():
    try:
        user_id = session.get('username')  # Assuming user_id is stored in session
        if not user_id:
            flash('You need to log in first.', 'info')
            return redirect(url_for('login'))  # Redirect to login if user is not logged in

        response = BorrowReturnRecordsTable.scan(
            FilterExpression=(Attr('status').eq('pending_borrow') | Attr('status').eq('pending_return') and Attr('isApprovedYet').eq('false'))
        )
        records = response['Items']
        return render_template('admin_req.html', records=records)
    except Exception as e:
        print(f"Error: {e}")
        return "An error occurred while fetching data from DynamoDB."
    return render_template('admin_req.html')

@app.route('/approve/<reqType>/<equipment_name>/<equipment_id>/<user_id>/<record_id>', methods=['POST'])
def approve_record(reqType,equipment_name, equipment_id, user_id,record_id):
    try:
        print(user_id)
        record_idNew = str(uuid.uuid4())
        local_tz = pytz.timezone('Asia/Bangkok')  # Replace with your local timezone
        now = datetime.now(local_tz)
        if reqType == 'borrow':
            due_date = (now + timedelta(weeks=1)).strftime('%Y-%m-%d %H:%M:%S')
            print(user_id)
            # Update the status in the Equipment table
            EquipmentTable.update_item(
                Key={'EquipmentID': equipment_id},
                UpdateExpression="set #s = :s, #u = :u , DueDate = :d , BorrowDate = :bd",
                ExpressionAttributeNames={'#s': 'Status','#u': 'BorrowerID'},
                ExpressionAttributeValues={':s': 'Not Available',':u': user_id , ':d': due_date , ':bd': now.strftime('%Y-%m-%d %H:%M:%S')},
                ReturnValues="UPDATED_NEW"
            )

            # Update the status in the BorrowReturnRecords table
            BorrowReturnRecordsTable.put_item(
            Item={
                'record_id': record_idNew,
                'user_id': user_id,
                'equipment_id': equipment_id,
                'equipment_name': equipment_name,
                'type': 'borrow',
                'record_date': now.strftime('%Y-%m-%d %H:%M:%S'),
                'due_date': due_date,
                'status': 'approved',
                'isApprovedYet': 'true'
            }
            )
            BorrowReturnRecordsTable.update_item(
                Key={'record_id': record_id},
                UpdateExpression="SET isApprovedYet = :a",
                ExpressionAttributeValues={':a': 'true'},
            )
        elif reqType == 'return':
            # Update the status in the Equipment table
            EquipmentTable.update_item(
                Key={'EquipmentID': equipment_id},
                UpdateExpression="set #s = :s, #d = :d, #borrowerId = :b, #borrowerDate = :bd",
                ExpressionAttributeNames={'#s': 'Status','#d': 'DueDate' ,'#borrowerId': 'BorrowerID', '#borrowerDate': 'BorrowDate'},
                ExpressionAttributeValues={':s': 'Available',':d': '-' , ':b': '-', ':bd': '-'},
                ReturnValues="UPDATED_NEW"
            )

            BorrowReturnRecordsTable.put_item(
            Item={
                'record_id': record_idNew,
                'user_id': user_id,
                'equipment_id': equipment_id,
                'equipment_name': equipment_name,
                'type': 'return',
                'record_date': now.strftime('%Y-%m-%d %H:%M:%S'),
                'due_date': '-',
                'status': 'approved',
                'isApprovedYet': 'true'
            }
            )
            BorrowReturnRecordsTable.update_item(
                Key={'record_id': record_id},
                UpdateExpression="SET isApprovedYet = :a",
                ExpressionAttributeValues={':a': 'true'},
            )
        return jsonify(success=True)
    except Exception as e:
        print(f"Error: {e}")
        return jsonify(success=False), 500

@app.route('/admin_list')
def admin_list():
    try:
        user_id = session.get('username')  # Assuming user_id is stored in session
        if not user_id:
            flash('You need to log in first.', 'info')
            return redirect(url_for('login'))  # Redirect to login if user is not logged in

        response = BorrowReturnRecordsTable.scan()
        records = response['Items']
        return render_template('admin_list.html', records=records)
    except Exception as e:
        print(f"Error: {e}")
        return "An error occurred while fetching data from DynamoDB."
    return render_template('admin_req.html')

@app.route('/admin_lenses')
def admin_lenses():
    return render_template('admin_lenses.html')

@app.route('/admin_equipment')
def admin_equipment():
    return render_template('admin_equipment.html')

@app.route('/admin_accessories')
def admin_accessories():
    return render_template('admin_accessories.html')

@app.route('/admin_camera')
def admin_camera():
    return render_template('admin_camera.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
