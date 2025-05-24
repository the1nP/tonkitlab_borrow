from pathlib import Path
import subprocess
import os
import sys

def update_aws_credentials():
    print("Paste your credentials in the format:\n"
          "aws_access_key_id = ...\naws_secret_access_key = ...\naws_session_token = ...\n")
    
    credentials_dict = {}
    expected_keys = {"aws_access_key_id", "aws_secret_access_key", "aws_session_token"}
    
    while len(credentials_dict) < 3:
        try:
            line = input().strip()
            if not line or "=" not in line:
                continue
            key, value = map(str.strip, line.split("=", 1))
            if key in expected_keys:
                credentials_dict[key] = value
        except EOFError:
            break

    if len(credentials_dict) < 3:
        print("❌ Incomplete input. All 3 fields are required.")
        return
    
    # ถามว่าจะเขียนไฟล์ไปที่ root หรือ user ปัจจุบัน
    print("\nWhere would you like to store the AWS credentials?")
    print("1. Current user (~/.aws/credentials)")
    print("2. Root user (/root/.aws/credentials) - requires sudo")
    
    choice = ""
    while choice not in ["1", "2"]:
        choice = input("Enter your choice (1 or 2): ").strip()
    
    if choice == "1":
        # เขียนไฟล์ไปที่ user ปัจจุบัน
        credentials_path = Path.home() / ".aws" / "credentials"
        credentials_path.parent.mkdir(exist_ok=True)

        with credentials_path.open("w") as f:
            f.write("[default]\n")
            for key in expected_keys:
                f.write(f"{key} = {credentials_dict[key]}\n")
        
        print(f"✅ AWS credentials updated at {credentials_path}")
        
    else:
        # เขียนไฟล์ไปที่ root user
        try:
            # ตรวจสอบว่าสามารถใช้ sudo ได้หรือไม่
            sudo_test = subprocess.run(["sudo", "-n", "true"], 
                                      stdout=subprocess.DEVNULL, 
                                      stderr=subprocess.DEVNULL, 
                                      check=False)
            
            if sudo_test.returncode != 0:
                print("⚠️ This operation requires sudo privileges.")
                print("You'll be prompted for your password...")
            
            # สร้างโฟลเดอร์ /root/.aws/ หากยังไม่มี
            subprocess.run(["sudo", "mkdir", "-p", "/root/.aws/"], check=True)
            
            # สร้างไฟล์ credentials ชั่วคราว
            temp_file = Path("/tmp/aws_credentials_temp")
            with temp_file.open("w") as f:
                f.write("[default]\n")
                for key in expected_keys:
                    f.write(f"{key} = {credentials_dict[key]}\n")
            
            # เขียนไฟล์ไปที่ /root/.aws/credentials โดยใช้ sudo
            subprocess.run(["sudo", "cp", str(temp_file), "/root/.aws/credentials"], check=True)
            subprocess.run(["sudo", "chmod", "600", "/root/.aws/credentials"], check=True)
            
            # ลบไฟล์ชั่วคราว
            temp_file.unlink()
            
            print("✅ AWS credentials updated at /root/.aws/credentials")
            
        except subprocess.CalledProcessError as e:
            print(f"❌ Error: {e}")
            print("Could not write credentials to /root/.aws/credentials")
            
            # ถามว่าต้องการลองเขียนไปที่ user ปัจจุบันแทนหรือไม่
            retry = input("\nWould you like to write to current user's credentials instead? (y/n): ").strip().lower()
            if retry == "y" or retry == "yes":
                credentials_path = Path.home() / ".aws" / "credentials"
                credentials_path.parent.mkdir(exist_ok=True)

                with credentials_path.open("w") as f:
                    f.write("[default]\n")
                    for key in expected_keys:
                        f.write(f"{key} = {credentials_dict[key]}\n")
                
                print(f"✅ AWS credentials updated at {credentials_path}")

if __name__ == "__main__":
    update_aws_credentials()