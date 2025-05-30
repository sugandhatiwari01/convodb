# Convo - Backend README

## Overview

The Convo backend is a Node.js application built with Express and MongoDB, powering the real-time chat functionality of the Convo app. It handles user authentication via Google OAuth, manages chat data, user profile pictures, and enables real-time messaging using Socket.IO. The backend ensures secure data storage and efficient communication with the frontend.

## Features

- **User Authentication**: Supports Google OAuth for secure login and signup.
- **Real-Time Messaging**: Uses Socket.IO for instant message delivery.
- **Data Management**: Stores user profiles, chat history, and profile pictures in MongoDB.
- **Profile Picture Management**: Allows users to upload and retrieve profile pictures via dedicated API endpoints.
- **RESTful API**: Provides endpoints for user management, message retrieval, profile picture handling, and chat operations.
- **CORS Support**: Configured to allow requests from the frontend application.

## Tech Stack

- **Node.js**: For server-side JavaScript runtime.
- **Express**: For building RESTful APIs and handling HTTP requests.
- **MongoDB/Mongoose**: For data storage and schema-based modeling.
- **Socket.IO**: For real-time, bidirectional communication.
- **Passport.js**: For Google OAuth authentication.
- **dotenv**: For environment variable management.
- **Multer**: For handling profile picture uploads.

## Prerequisites

- Node.js (v16 or higher)
- MongoDB (local or MongoDB Atlas)
- Google OAuth credentials
- npm

## Installation

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/your-username/convo-backend.git
   cd convo-backend
   ```

2. **Install Dependencies**:

   ```bash
   npm install
   ```

3. **Set Up Environment Variables**: Create a `.env` file in the root directory and add the following:

   ```
   MONGODB_URI=mongodb://localhost:27017/convo
   GOOGLE_CLIENT_ID=your-google-client-id
   GOOGLE_CLIENT_SECRET=your-google-client-secret
   SESSION_SECRET=your-session-secret
   FRONTEND_URL=http://localhost:5173
   PORT=5000
   ```

   Replace placeholders with your MongoDB URI, Google OAuth credentials, and a secure session secret.

4. **Run the Application**:

   ```bash
   npm start
   ```

5. The server will run on `http://localhost:5000` (or the port specified in `.env`).

## API Endpoints

- `GET /auth/google`: Initiates Google OAuth login.
- `GET /auth/google/callback`: Handles Google OAuth callback.
- `GET /api/users`: Retrieves authenticated user data.
- `POST /api/users/register`: Registers a new user.
- `POST /api/users/login`: Authenticates a user.
- `POST /api/messages`: Sends a new message.
- `GET /api/messages/:chatId`: Retrieves messages for a specific chat.
- `POST /api/user/profile-pic`: Uploads a user profile picture.
- `GET /api/user/profile-pic/:username`: Retrieves a user’s profile picture.

## Socket.IO Events

- `connection`: Establishes a WebSocket connection.
- `sendMessage`: Emits a new message to the chat room.
- `receiveMessage`: Listens for incoming messages in real time.

## Deployment

- Deploy the backend on Render by connecting your GitHub repository.
- Set environment variables in the hosting platform’s dashboard.
- Use MongoDB Atlas for production to avoid local database issues.
- Update CORS settings to allow the deployed frontend URL (e.g., Vercel domains).
- Ensure the `uploads/` directory is configured for persistent storage on Render.
