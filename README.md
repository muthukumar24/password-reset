# password-reset
This Repository is created for submitting the allocated task from node js day -5 session.

Task Details
-
The task is to implement a correct password reset flow with email verification and proper update of the new password in data base for the web app.

1 - design a forget password page, where the user should enters his email id

2 - check if the user exists in db

3 - if the user is not present send an error message

4 - if the user is found generate a random string and send a link with that random string in the mail

5 - store the random string in db for the later verification

6 - when user enters that link retrieve the random string and pass it to db

7 - check if the random string matches

8 - if the string the matches show the password reset form

9 - store the new password and clear the random string in db once the user submits the form

10 - if the string does not match send an error message

Application Workflow
-
Sign-Up Workflow:

- User Action: User fills out and submits the sign-up form with username, email, and password.

- Server Processing: Server checks if the email is already registered. If not, the server hashes the password and saves the new user details in the database.

- Response: If successful, the server responds with a success message. If the user already exists, the server responds with an error message.

Login Workflow:

- User Action: User fills out and submits the login form with email and password.

- Server Processing: Server verifies if the user exists and the password matches. If valid, the server generates a JWT token.

- Response: If successful, the server sends the token back to the client. If invalid, the server responds with an error message and If the login is successful, the front-end stores the token and redirects the user to the home page. If the login is unsuccessful, the front-end displays an error message to the user.

Forgot Password Workflow:

- User Action: User fills out and submits the forgot password form with their email.

- Server Processing: Server checks if the email is registered.
If registered, the server generates a reset token and saves it in the database. Server sends a reset link containing the token to the user's email.

- Response: If successful, the server responds that the reset link was sent. If the email is not registered, the server responds with an error message.

Reset Password Workflow:

- User Action: User clicks the reset link in their email, leading to a reset password form. User fills out and submits the form with the new password and confirmation.

- Server Processing: Server verifies the reset token and checks if it's not expired. If valid, the server hashes the new password and updates the user's password in the database.

- Response: If successful, the server responds that the password was reset. If invalid or expired, the server responds with an error message.

Please refer to the "Screenshots" folder for application workflow screenshots.

Please refer to the following files for source code

- /models/user.js
- /routes/api.js
- server.js

Thankyou and Awaiting Feedback.
