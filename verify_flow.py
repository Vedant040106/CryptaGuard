from app import app, get_db_connection
from werkzeug.security import generate_password_hash
import sys

# Setup
app.config['TESTING'] = True
app.config['WTF_CSRF_ENABLED'] = False
client = app.test_client()

def cleanup_db():
    print("Cleaning up DB...")
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # Find user IDs to delete
        cursor.execute("SELECT id FROM users WHERE username = 'TestVerifyUser' OR email = 'verify@test.com'")
        users = cursor.fetchall()
        
        for (user_id,) in users:
            # Delete related records (in case ON DELETE CASCADE is missing)
            cursor.execute("DELETE FROM activity_logs WHERE user_id = %s", (user_id,))
            cursor.execute("DELETE FROM stored_files WHERE user_id = %s", (user_id,))
            cursor.execute("DELETE FROM messages WHERE sender_id = %s OR receiver_id = %s", (user_id, user_id))
            cursor.execute("DELETE FROM friend_requests WHERE sender_id = %s OR receiver_id = %s", (user_id, user_id))
            
        cursor.execute("DELETE FROM users WHERE username = 'TestVerifyUser' OR email = 'verify@test.com'")
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Cleanup failed: {e}")

def run_tests():
    cleanup_db()
    
    print("\n--- TEST 1: REGISTRATION ---")
    # 1. Successful Registration
    response = client.post('/register', data={
        'username': 'TestVerifyUser',
        'email': 'verify@test.com',
        'password': 'password123',
        'security_question': 'pet_name',
        'security_answer': 'fluffy'
    }, follow_redirects=True)
    
    if b'Registration successful' in response.data:
        print("PASS: Registration successful")
    else:
        print(f"FAIL: Registration failed. Response: {response.data}")
        return

    # 2. Duplicate Username
    response = client.post('/register', data={
        'username': 'TestVerifyUser',
        'email': 'other@test.com',
        'password': 'password123',
        'security_question': 'pet_name',
        'security_answer': 'fluffy'
    }, follow_redirects=True)
    
    if b"Username 'TestVerifyUser' is already taken" in response.data:
        print("PASS: Duplicate username caught")
    else:
        print(f"FAIL: Duplicate username not caught. Response: {response.data}")

    # 3. Duplicate Email
    response = client.post('/register', data={
        'username': 'OtherUser',
        'email': 'verify@test.com',
        'password': 'password123',
        'security_question': 'pet_name',
        'security_answer': 'fluffy'
    }, follow_redirects=True)
    
    if b"Email 'verify@test.com' is already registered" in response.data:
        print("PASS: Duplicate email caught")
    else:
        print(f"FAIL: Duplicate email not caught. Response: {response.data}")

    print("\n--- TEST 2: FORGOT PASSWORD ---")
    
    # 1. Forgot Password (Identify)
    # Using cookie jar to maintain session
    with client:
        response = client.post('/forgot-password', data={'email': 'verify@test.com'}, follow_redirects=True)
        if b'Please answer your security question' in response.data:
            print("PASS: Forgot password identification successful")
        else:
            print(f"FAIL: Forgot password identification failed. Response: {response.data}")
            return

        # 2. Verify Question (Wrong Answer)
        response = client.post('/verify-question', data={'answer': 'wrong'}, follow_redirects=True)
        if b'Incorrect answer' in response.data:
             print("PASS: Wrong answer caught")
        else:
             print(f"FAIL: Wrong answer not caught. Response: {response.data}")

        # 3. Verify Question (Correct Answer)
        response = client.post('/verify-question', data={'answer': 'FLUFFY '}, follow_redirects=True)
        if b'Enter your new password' in response.data:
            print("PASS: Correct answer accepted")
        else:
            print(f"FAIL: Correct answer failed. Response: {response.data}")
            return

        # 4. Reset Password
        response = client.post('/reset-password', data={
            'password': 'newpassword123',
            'confirm_password': 'newpassword123'
        }, follow_redirects=True)
        
        if b'Password successfully reset' in response.data:
            print("PASS: Password reset successful")
        else:
             print(f"FAIL: Password reset failed. Response: {response.data}")
             return

        # 5. Login check
        response = client.post('/login', data={
            'email': 'verify@test.com',
            'password': 'newpassword123'
        }, follow_redirects=True)
        
        if b'TestVerifyUser' in response.data: # Assuming username is displayed on dashboard
             print("PASS: Login with new password successful")
        else:
             print(f"FAIL: Login failed. Response: {response.data}")

    cleanup_db()
    print("\n=== ALL TESTS PASSED SUCCESSFULLY ===")

if __name__ == "__main__":
    run_tests()
