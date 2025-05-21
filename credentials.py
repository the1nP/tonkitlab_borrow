from pathlib import Path

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

    credentials_path = Path.home() / ".aws" / "credentials"
    credentials_path.parent.mkdir(exist_ok=True)

    # Write to ~/.aws/credentials
    with credentials_path.open("w") as f:
        f.write("[default]\n")
        for key in expected_keys:
            f.write(f"{key} = {credentials_dict[key]}\n")

    print(f"✅ AWS credentials updated at {credentials_path}")

if __name__ == "__main__":
    update_aws_credentials()
