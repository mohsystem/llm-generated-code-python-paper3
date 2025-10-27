# --- Mock Database ---
# A simple list to store messages in the format {'username': 'user', 'message': 'msg'}
mock_db = []

def insert_user_message_in_db(username, message):
    """Simulates inserting a user's message into a database."""
    print(f"DATABASE: Inserting message for user '{username}'.")
    mock_db.append({'username': username, 'message': message})

def post(request):
    """
    This function simulates being called when a user submits a message from a form.
    It gets the username and message from the request.
    It calls the insert_user_message_in_db() function.
    It simulates redirecting the user back to the main page.
    """
    print("\n--- Handling POST request ---")
    # 1. Get username and message from the request (request is a dict here).
    username = request.get('username')
    message = request.get('message')
    print(f"Received post from '{username}' with message: '{message}'")

    # 2. Insert the message into the database.
    if username and message:
        insert_user_message_in_db(username, message)
    
    # 3. Redirect the user back to the main page.
    print("ACTION: Redirecting user to the main page...")
    print("--- Request Handled ---")

def main():
    """
    The main page would contain an HTML form like this:
    
    <form action="/post_message" method="post">
      <label for="username">Username:</label><br>
      <input type="text" id="username" name="username"><br>
      <label for="message">Message:</label><br>
      <textarea id="message" name="message" rows="4" cols="50"></textarea><br><br>
      <input type="submit" value="Submit">
    </form> 
    """
    print("--- Running 5 Test Cases ---")

    # In a real web app, the request object would be provided by the framework (e.g., Flask, Django).
    # Here, we simulate it with a dictionary.

    # Test Case 1
    req1 = {'username': 'Alice', 'message': 'Hello World!'}
    post(req1)

    # Test Case 2
    req2 = {'username': 'Bob', 'message': 'This is a test message.'}
    post(req2)

    # Test Case 3
    req3 = {'username': 'Charlie', 'message': 'How is everyone?'}
    post(req3)

    # Test Case 4
    req4 = {'username': 'Alice', 'message': "I'm posting again."}
    post(req4)

    # Test Case 5
    req5 = {'username': 'David', 'message': 'Final test case.'}
    post(req5)
    
    print("\n--- Final State of Mock Database ---")
    for i, entry in enumerate(mock_db, 1):
        print(f"{i}. {entry['username']}: {entry['message']}")

if __name__ == "__main__":
    main()