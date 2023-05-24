#### To test the RESTful API, use Postman:

1. Generate JWT Token:

> Make a POST request to http://localhost:8080/login with the following JSON payload containing the username and password:

```json
{
  "username": "user1",
  "password": "password1"
}
```

Retrieve the JWT token from the response. Copy it

2. Create a Task:

> Make a POST request to http://localhost:8080/tasks with the following JSON containing the task details and the JWT token in the Authorization header:

```json
{
  "title": "Task 1",
  "description": "Description 1",
  "dueDate": "2023-04-24"
}
```

3. Get all Tasks:

> Make a GET request to http://localhost:8080/tasks with the JWT token in the Authorization header.

4. Update a Task:

> Make a PUT request to http://localhost:8080/tasks/{taskID} (replace {taskID} with the actual task ID) with the updated task details:

```json
{
  "title": "Updated Task 1",
  "description": "Updated Description 1",
  "dueDate": "2023-04-24"
}
```

5. Delete a Task:

> Make a DELETE request to http://localhost:8080/tasks/{taskID} (replace {taskID} with the actual task ID) with the JWT token in the Authorization headerS
