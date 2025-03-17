# Image & Video Uploader & Downloader

A simple web application for uploading, downloading, and managing encrypted images and videos built with Node.js, Express, and MongoDB.

## Features

- **Secure File Storage:** Files are encrypted using AES-256-CBC.
- **Multiple File Upload:** Upload one or more images/videos at once.
- **Download Options:** Download files individually or in bulk as a ZIP archive.
- **File Management:** Delete individual files or use bulk delete.
- **Responsive Gallery:** User-friendly gallery view with select mode.

## Prerequisites

- [Node.js](https://nodejs.org/) (v14+ recommended)
- [MongoDB](https://www.mongodb.com/)

## Installation

1. **Clone the repository:**

    ```bash
    git clone https://github.com/your-username/your-project.git
    cd your-project
    ```

2. **Install dependencies:**
    ```bash
    npm install
    ```
3. **Set up Environment Variables:**
    Create a **.env** file in the project root with the following content:
    ```bash
    PORT=3000
    SECRET_KEY=your_secret_key_here
    PASSWORD=your_password_here
    MONGO_URI=MONGO_URI
    ```

## Usage

1. Start the server:
    ```
    npm run start
    ```
2. Access the Application:
    ```
    http://localhost:PORT/?password=your_password_here
    ```