import os
import subprocess

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

    # สร้างคำสั่ง export commands สำหรับ Linux
    export_commands = [
        f"export AWS_ACCESS_KEY_ID=\"{credentials_dict['aws_access_key_id']}\"",
        f"export AWS_SECRET_ACCESS_KEY=\"{credentials_dict['aws_secret_access_key']}\"",
        f"export AWS_SESSION_TOKEN=\"{credentials_dict['aws_session_token']}\""
    ]

    # สำหรับการทดสอบในโปรแกรมปัจจุบัน (จะมีผลเฉพาะใน process นี้)
    os.environ["AWS_ACCESS_KEY_ID"] = credentials_dict['aws_access_key_id']
    os.environ["AWS_SECRET_ACCESS_KEY"] = credentials_dict['aws_secret_access_key'] 
    os.environ["AWS_SESSION_TOKEN"] = credentials_dict['aws_session_token']
    
    print("✅ AWS credentials exported to environment variables for the current process")
    print("\nTo make these variables available in your shell, copy and paste these commands:")
    for cmd in export_commands:
        print(cmd)
        
    print("\nOr run this in one line:")
    print("; ".join(export_commands))
    
    print("\nTo add these permanently to your shell profile, add the following lines to your ~/.bashrc or ~/.zshrc:")
    for cmd in export_commands:
        print(cmd)

    # ถามผู้ใช้ว่าต้องการคัดลอกคำสั่งไปยัง clipboard หรือไม่
    print("\nWould you like to copy the export commands to clipboard? (y/n)")
    choice = input().strip().lower()
    
    if choice == 'y' or choice == 'yes':
        try:
            commands_text = "\n".join(export_commands)
            # ใช้ xclip หรือ xsel เพื่อคัดลอกข้อความไปยัง clipboard (ต้องติดตั้งก่อน)
            try:
                process = subprocess.Popen(['xclip', '-selection', 'clipboard'], stdin=subprocess.PIPE)
                process.communicate(commands_text.encode())
                print("✅ Commands copied to clipboard!")
            except FileNotFoundError:
                try:
                    process = subprocess.Popen(['xsel', '--clipboard', '--input'], stdin=subprocess.PIPE)
                    process.communicate(commands_text.encode())
                    print("✅ Commands copied to clipboard!")
                except FileNotFoundError:
                    print("❌ Could not copy to clipboard. xclip or xsel is not installed.")
                    print("Install them with: sudo apt install xclip or sudo apt install xsel")
        except Exception as e:
            print(f"❌ Failed to copy: {str(e)}")

if __name__ == "__main__":
    update_aws_credentials()