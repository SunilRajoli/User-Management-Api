# user-management-api

In this project, we are going to create User-Management-Api system. We will take a look at how to create login, registration, profile, reset password routes and learn how to send Mail from the Node.js backend application. 


Download this project from above link. Create two configaration files into the project. First in the client and second in the server.

In the Client Folder create .env file and put this code inside it.

.env

REACT_APP_SERVER_DOMAIN='<server_domain>' # example 'http://localhost:8080'

After that create a file in the Server Folder with the name config.js and put the below code inside it.

config.js

export default {
    JWT_SECRET : "<secret>",
    EMAIL: "tina.jacobi78@ethereal.email",
    PASSWORD : "Vr18M7vVY2XQFredmg",
    ATLAS_URI: "<MONGODB_ATLAS_URI>"
}