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
    username = session.get('username')
    access_token = session.get('access_token')
    if not username or not access_token:
        flash('You need to log in first.', 'error')
        return redirect(url_for('login'))
    try:
        # ดึงข้อมูลผู้ใช้จาก Cognito
        response = cognito.get_user(
            AccessToken=access_token
        )
        user_attributes = {attr['Name']: attr['Value'] for attr in response['UserAttributes']}
        role = user_attributes.get('custom:role')

        # ตรวจสอบบทบาทของผู้ใช้
        if role == 'admin':
            return render_template('admin_home.html')
        else:
            return render_template('home.html')

    except ClientError as e:
        error_message = e.response['Error']['Message']
        print(f"Error: {error_message}")
        flash(error_message, 'error')
        return redirect(url_for('login'))

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
        }

        # ตรวจสอบว่าเป็นแอดมินหรือไม่
        role = user_attributes.get('custom:role')
        if role == 'admin':
            return render_template('admin_profile.html', user_info=user_info)
        else:
            return render_template('profile.html', user_info=user_info)

    except ClientError as e:
        error_message = e.response['Error']['Message']
        print(f"Error: {error_message}")
        flash(error_message, 'error')
        return redirect(url_for('login'))

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
        
        # ลบ username ชั่วคราวจาก session
        session.pop('temp_username', None)
        
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

@app.route('/details_camera')
def details_camera():
    try:
        response = EquipmentTable.scan(
            FilterExpression=Attr('Category').eq('Cameras')
        )
        items = response['Items']
        # ตรวจสอบว่ามีฟิลด์ isMemberRequired หรือไม่
        for item in items:
            item['isMemberRequired'] = item.get('isMemberRequired', 'no')  # ค่าเริ่มต้นเป็น 'no' ถ้าไม่มีฟิลด์นี้
        return render_template('detailscamera.html', items=items)
    except Exception as e:
        print(f"Error: {e}")
        return "An error occurred while fetching data from DynamoDB."

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

        user_response = cognito.get_user(AccessToken=access_token)
        user_attributes = {attr['Name']: attr['Value'] for attr in user_response['UserAttributes']}
        club_member = user_attributes.get('custom:club_member', 'no')

        is_member_required = equipment_item.get('isMemberRequired', 'no')
        if is_member_required == 'yes' and club_member != 'yes':
            return jsonify(success=False, message="This equipment is restricted to members only"), 403

        # Step 3: Create borrow request record
        local_tz = pytz.timezone('Asia/Bangkok')
        now = datetime.now(local_tz)
        record_id = str(uuid.uuid4())
        user_id = session.get('username')

        BorrowReturnRecordsTable.put_item(
            Item={
                'record_id': record_id,
                'user_id': user_id,
                'equipment_id': equipment_id,
                'equipment_name': equipment_item['Name'],
                'RequestType': 'borrow',  # เพิ่ม RequestType
                'record_date': now.strftime('%Y-%m-%d %H:%M:%S'),
                'due_date': '-',
                'StatusReq': 'Pending',
                'isApprovedYet': 'false'
            }
        )

        return jsonify(success=True, message="Borrow request submitted successfully")

    except Exception as e:
        print(f"Error: {e}")
        return jsonify(success=False, message="An unexpected error occurred"), 500

@app.route('/details_lenses')
def details_lenses():
    try:
        response = EquipmentTable.scan(
            FilterExpression=Attr('Category').eq('Lenses')
        )
        items = response['Items']
        # เพิ่ม isMemberRequired ถ้าไม่มี
        for item in items:
            item['isMemberRequired'] = item.get('isMemberRequired', 'no')
        return render_template('detailslenses.html', items=items)
    except Exception as e:
        print(f"Error: {e}")
        return "An error occurred while fetching data from DynamoDB."

@app.route('/details_accessories')
def details_accessories():
    try:
        response = EquipmentTable.scan(
            FilterExpression=Attr('Category').eq('Accessories')
        )
        items = response['Items']
        # เพิ่ม isMemberRequired ถ้าไม่มี
        for item in items:
            item['isMemberRequired'] = item.get('isMemberRequired', 'no')
        return render_template('detailsaccessories.html', items=items)
    except Exception as e:
        print(f"Error: {e}")
        return "An error occurred while fetching data from DynamoDB."

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
        data = request.get_json()
        local_tz = pytz.timezone('Asia/Bangkok')
        now = datetime.now(local_tz)
        record_id = str(uuid.uuid4())
        
        BorrowReturnRecordsTable.put_item(
            Item={
                'record_id': record_id,
                'user_id': data['user_id'],
                'equipment_id': data['equipment_id'],
                'equipment_name': data['equipment_name'],
                'RequestType': 'return',  # กำหนดค่า RequestType เป็น 'return'
                'record_date': now.strftime('%Y-%m-%d %H:%M:%S'),
                'due_date': data['due_date'],
                'StatusReq': 'Pending',
                'isApprovedYet': 'false'
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
            'message': 'Failed to submit return request'
        }), 500

@app.route('/admin_req')
def admin_req():
    try:
        # ดึงคำขอที่มี StatusReq เป็น Pending
        response = BorrowReturnRecordsTable.scan(
            FilterExpression=Attr('StatusReq').eq('Pending')
        )
        
        if 'Items' in response:
            records = response['Items']
            # เรียงลำดับตามวันที่บันทึก (ล่าสุดขึ้นก่อน)
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

        # อัพเดต StatusReq และ RequestType ใน BorrowReturnRecords
        update_expression = "SET StatusReq = :s, isApprovedYet = :a"
        expression_values = {
            ':s': 'Approved',
            ':a': 'true'
        }

        # เพิ่มการอัพเดต RequestType เมื่อเป็นการคืน
        if reqType == 'return':
            update_expression += ", RequestType = :r"
            expression_values[':r'] = 'return'

        BorrowReturnRecordsTable.update_item(
            Key={'record_id': record_id},
            UpdateExpression=update_expression,
            ExpressionAttributeValues=expression_values
        )

        # อัพเดตจำนวน, StatusEquipment และ due_date ใน Equipment
        equipment = EquipmentTable.get_item(Key={'EquipmentID': equipment_id})
        if 'Item' in equipment:
            current_quantity = int(equipment['Item'].get('Quantity', 0))
            
            if reqType == 'borrow':
                new_quantity = current_quantity - 1
                # อัพเดตข้อมูลการยืม
                EquipmentTable.update_item(
                    Key={'EquipmentID': equipment_id},
                    UpdateExpression="SET Quantity = :q, StatusEquipment = :s, due_date = :d, BorrowDate = :bd, BorrowerID = :uid",
                    ExpressionAttributeValues={
                        ':q': new_quantity,
                        ':s': 'Available' if new_quantity > 0 else 'Not Available',
                        ':d': due_date,
                        ':bd': borrow_date,
                        ':uid': user_id
                    }
                )
            elif reqType == 'return':
                # ...existing return logic...
                new_quantity = current_quantity + 1
                EquipmentTable.update_item(
                    Key={'EquipmentID': equipment_id},
                    UpdateExpression="SET Quantity = :q, StatusEquipment = :s, due_date = :d, BorrowDate = :bd, BorrowerID = :uid",
                    ExpressionAttributeValues={
                        ':q': new_quantity,
                        ':s': 'Available' if new_quantity > 0 else 'Not Available',
                        ':d': '-',
                        ':bd': '-',
                        ':uid': '-'
                    }
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
    try:
        response = EquipmentTable.scan(
            FilterExpression=Attr('Category').eq('Lenses')
        )
        items = response['Items']
        return render_template('admin_lenses.html', items=items)
    except Exception as e:
        print(f"Error: {e}")
        return "An error occurred while fetching data from DynamoDB."

@app.route('/admin_equipment')
def admin_equipment():
    try:
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

            response = EquipmentTable.scan(
                FilterExpression=Attr('Name').eq(name) & Attr('Category').eq(category)
            )
            items = response['Items']

            if items:
                existing_item = items[0]
                current_quantity = int(existing_item.get('Quantity', 0))
                new_quantity = current_quantity + quantity

                EquipmentTable.update_item(
                    Key={'EquipmentID': existing_item['EquipmentID']},
                    UpdateExpression='SET #qty = :new_qty, #st = :new_status, #member = :member_req',
                    ExpressionAttributeNames={
                        '#qty': 'Quantity',
                        '#st': 'StatusEquipment',
                        '#member': 'isMemberRequired'
                    },
                    ExpressionAttributeValues={
                        ':new_qty': new_quantity,
                        ':new_status': 'Available' if new_quantity > 0 else 'Not Available',
                        ':member_req': isMemberRequired
                    }
                )
            else:
                equipment_id = str(uuid.uuid4())
                EquipmentTable.put_item(
                    Item={
                        'EquipmentID': equipment_id,
                        'Name': name,
                        'Category': category,
                        'StatusEquipment': 'Available' if quantity > 0 else 'Not Available',
                        'Quantity': quantity,
                        'DueDate': '-',
                        'BorrowerID': '-',
                        'BorrowDate': '-',
                        'isMemberRequired': isMemberRequired
                    }
                )

            redirect_url = url_for('admin_camera') if category == 'Cameras' else \
                         url_for('admin_accessories') if category == 'Accessories' else \
                         url_for('admin_lenses') if category == 'Lenses' else \
                         url_for('admin_equipment')
            
            return jsonify({
                'success': True,
                'message': f'Success! Added {quantity} units of {name}',
                'name': name,
                'quantity': quantity,
                'isUpdate': False,
                'redirect': redirect_url
            })

        except Exception as e:
            print(f"Error in admin_add_equipment: {e}")
            return jsonify({
                'success': False,
                'message': 'Failed to add equipment. Please try again.'
            })

    return render_template('admin_add_equipment.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
