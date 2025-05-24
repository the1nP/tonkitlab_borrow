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
    
    # สร้างคำสั่ง sudo export commands สำหรับ root user
    sudo_export_commands = [
        f"sudo -i bash -c 'export AWS_ACCESS_KEY_ID=\"{credentials_dict['aws_access_key_id']}\"'",
        f"sudo -i bash -c 'export AWS_SECRET_ACCESS_KEY=\"{credentials_dict['aws_secret_access_key']}\"'", 
        f"sudo -i bash -c 'export AWS_SESSION_TOKEN=\"{credentials_dict['aws_session_token']}\"'"
    ]
    
    # คำสั่งเพื่อเขียนลงใน /root/.bashrc
    root_bashrc_commands = [
        f"echo 'export AWS_ACCESS_KEY_ID=\"{credentials_dict['aws_access_key_id']}\"' | sudo tee -a /root/.bashrc > /dev/null",
        f"echo 'export AWS_SECRET_ACCESS_KEY=\"{credentials_dict['aws_secret_access_key']}\"' | sudo tee -a /root/.bashrc > /dev/null",
        f"echo 'export AWS_SESSION_TOKEN=\"{credentials_dict['aws_session_token']}\"' | sudo tee -a /root/.bashrc > /dev/null"
    ]

    # สำหรับการทดสอบในโปรแกรมปัจจุบัน (จะมีผลเฉพาะใน process นี้)
    os.environ["AWS_ACCESS_KEY_ID"] = credentials_dict['aws_access_key_id']
    os.environ["AWS_SECRET_ACCESS_KEY"] = credentials_dict['aws_secret_access_key'] 
    os.environ["AWS_SESSION_TOKEN"] = credentials_dict['aws_session_token']
    
    print("✅ AWS credentials exported to environment variables for the current process")
    
    print("\n--- For Current User ---")
    print("To make these variables available in your shell, copy and paste these commands:")
    for cmd in export_commands:
        print(cmd)
        
    print("\nOr run this in one line:")
    print("; ".join(export_commands))
    
    print("\n--- For Root User (requires sudo) ---")
    print("To set environment variables for root user's current session:")
    for cmd in sudo_export_commands:
        print(cmd)
    
    print("\nTo add these permanently to root's profile:")
    for cmd in root_bashrc_commands:
        print(cmd)
    
    print("\nOr run this one line command to add them permanently to root's .bashrc:")
    print("; ".join(root_bashrc_commands))
    
    print("\n--- For Permanent Setup ---")
    print("To add these permanently to your shell profile, add the following lines to your ~/.bashrc or ~/.zshrc:")
    for cmd in export_commands:
        print(cmd)

    # ถามผู้ใช้ว่าต้องการคัดลอกคำสั่งไปยัง clipboard หรือไม่
    print("\nWhat would you like to copy to clipboard?")
    print("1. Current user export commands")
    print("2. Root user export commands (for current session)")
    print("3. Root user permanent setup commands")
    print("4. Nothing")
    choice = input("Enter your choice (1-4): ").strip()
    
    if choice == '1':
        commands_text = "\n".join(export_commands)
        copy_to_clipboard(commands_text, "Current user export commands")
    elif choice == '2':
        commands_text = "\n".join(sudo_export_commands)
        copy_to_clipboard(commands_text, "Root user export commands")
    elif choice == '3':
        commands_text = "\n".join(root_bashrc_commands)
        copy_to_clipboard(commands_text, "Root user permanent setup commands")
    else:
        print("No commands copied.")

def copy_to_clipboard(text, description):
    try:
        # ใช้ xclip หรือ xsel เพื่อคัดลอกข้อความไปยัง clipboard
        try:
            process = subprocess.Popen(['xclip', '-selection', 'clipboard'], stdin=subprocess.PIPE)
            process.communicate(text.encode())
            print(f"✅ {description} copied to clipboard!")
        except FileNotFoundError:
            try:
                process = subprocess.Popen(['xsel', '--clipboard', '--input'], stdin=subprocess.PIPE)
                process.communicate(text.encode())
                print(f"✅ {description} copied to clipboard!")
            except FileNotFoundError:
                print("❌ Could not copy to clipboard. xclip or xsel is not installed.")
                print("Install them with: sudo apt install xclip or sudo apt install xsel")
    except Exception as e:
        print(f"❌ Failed to copy: {str(e)}")

if __name__ == "__main__":
    update_aws_credentials()