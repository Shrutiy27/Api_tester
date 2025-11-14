# 🚀K API Tester – A Tkinter-Based Desktop App for API Testing

The **K API Tester** is a lightweight, user-friendly desktop application built using **Python’s Tkinter** library.  
It allows you to send and test REST API requests directly from your computer — no browser extensions or heavy tools like Postman required.

This project focuses on **simplicity, functionality, and a clean modern interface** that adapts to both light and dark themes.

---

## 📘 Project Overview

The goal of this project was to create a compact yet powerful tool that lets developers:

- Test different API endpoints quickly  
- View all parts of the response in one place  
- Save frequently used requests  
- Export responses for documentation or debugging  
- Use environment variables for flexible URL management  

---

### 🎥 Demo Link

> 🔗 **API Tester Demo:** [Watch Demo on Google Drive](https://drive.google.com/file/d/1YTr7werZ6IkyY_LLjKL473ALDqfNeh9H/view?usp=drivesdk)

## 🔽 Executable File Download
You can download the lateversionion of **K API Tester** here:

👉 [Download K API Tester (.exe)](
https://github.com/SharathHarish/API-Tester-K/releases/download/v1.0.0/K.API.Tester.exe)
---

## ✨ Features and Concepts Explained

### 1. 🖥️ Modern Tkinter Interface
Tkinter is known for being simple but not always visually appealing.  
To overcome that, this app uses **custom themes and layout management** to create a clean, modern-looking interface.  
It automatically resizes to fit 90% of your screen and centers itself on startup, making it look professional and responsive on any display.

---

### 2. 🌗 Light & Dark Themes
Switch between light and dark modes smoothly **without flickering or resizing**.  
When you toggle the theme, the app remembers the exact geometry and reapplies it, ensuring that nothing “jumps” or shifts on screen.

---

### 3. 🌐 API Request Support
You can test **GET, POST, PUT, and DELETE** requests.  
Each request can include:

- Custom headers (key-value pairs)  
- JSON request body  
- URLs with placeholders like `{{base_url}}`, which automatically replace values from the environment file  

**Example:**

If your `default.json` file contains:
```json
{
  "base_url": "https://jsonplaceholder.typicode.com"
}

Then a request to:

{{base_url}}/posts/1

will automatically resolve to:

https://jsonplaceholder.typicode.com/posts/1

```
---

4. 📦 Unified Response Output

Instead of splitting results into multiple tabs, the API Tester shows everything — status code, response headers, and response body — in a single output box.
If the body contains valid JSON, it’s automatically formatted for readability.


---

5. 🕒 Request History

Every request you send is saved in the history panel on the left.
You can double-click any entry to replay it instantly.
The app stores up to 20 recent requests in /data/history.json, so your history persists between sessions.


---

6. 💾 Save Requests to Collections

You can save frequently used requests as JSON files inside /collections/, including their method, URL, headers, and body.
This allows you to easily organize and reload saved API calls later.


---

7. 📤 Export Response

Each response can be exported to a .txt or .json file for documentation or debugging.
The “Export Response” button (located beside the Response label) saves the entire output — status, headers, and body — in one click.


---

8. 🧹 Clear Fields

The Clear button resets all inputs and outputs so you can start a new test instantly — without restarting the app.


---

9. 🔒 Environment Variables (Hidden but Functional)

The app silently loads:

/environments/default.json

This allows you to define key-value pairs (like base_url or auth_token) used in any request, without cluttering the interface.


---

10. 🛡️ Error Handling & Stability

Built with Python’s requests library, the app handles errors gracefully:

Invalid JSON bodies

Network timeouts

Connection errors

Non-JSON responses


If something goes wrong, you’ll see a clear error message in the response box instead of a crash.


---

🧰 Tech Stack

Component	Description

Language:	Python 3.8+
GUI:	Tkinter
Networking:	Requests
Storage	:JSON Files (History, Collections, Environment)



---

📂 Project Structure
```
API-Tester/
│
├── main(1).py                # Main Python script for the API Tester app
├── requirements.txt          # Python dependencies for running the app
├── README.md                 # Project documentation
└── assets/                   # Screenshots for this README
    ├── light_theme.png
    ├── dark_theme.png
    ├── get_method.png
    ├── post_method.png
    ├── export_feature.png
    └── exception_handling.png
```

---

🖼️ Screenshots

🌞 Light Theme

<p align="center">
   <img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/a780b244-e4e6-4b2e-8c85-5817ce940ea9" />
</p>
---

🌙 Dark Theme

<p align="center">
  <img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/36755614-2f7e-4966-8587-d587d81c9b25" />
</p>
---

🔍 GET Method Example

<p align="center">
  <img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/39a26780-e754-43e5-b55c-6fcd3bebb145" />
</p>
---

📨 POST Method Example

<p align="center">
  <img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/e2becc2c-1cf8-4739-9623-049b5291feb4" />
</p>
---

📁 Export Feature

<p align="center">
  <img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/44fb2789-1043-4ba0-94b0-4a20cc658f2c" />
</p>
---

⚠️ Exception Handling

<p align="center">
  <img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/7578f987-c4c3-47b0-a05a-bab838c0728a" />
</p>
---

🧠 Challenges Faced

1. Making Tkinter Look Modern
Fine-tuned colors, padding, and font styles for a clean UI.


2. Preventing Layout Shifts
Locked window geometry before theme changes to prevent UI jumps.


3. Merging Response Tabs
Combined Raw, JSON, and Headers views into one unified display.


4. Handling Multiple Content Types
Added fallback for non-JSON responses to prevent crashes.


5. Keeping It Lightweight
Avoided external libraries — only requests is used.


6. EXE Crashing Due to Missing .ico File
Fixed PyInstaller build with:

pyinstaller --onefile --noconsole --icon=icon.ico main.py


7. Blurry Icon on Windows Scaling
Replaced with a multi-resolution .ico (16×16 to 256×256) for crisp rendering.




---

⚙️ Installation (Single EXE File)

No Python or library installation required — the app runs as a standalone executable.

🪟 Windows Installation Steps

1. Download the File
Go to the Releases section and download K API Tester.exe.


2. Run the App
Double-click K API Tester.exe — no setup needed.


3. Automatic Setup (First Launch)
Creates folders if missing:

/environments
/collections
/data


4. Start Testing APIs!
Enter a URL, choose a method, and click Send.
View the response, status, and headers in one window.




---

📜 License

This project is licensed under the MIT License — you are free to use, modify, and distribute it for personal or commercial purposes.


---

🏁 Final Note

This project was an exciting journey in combining GUI development and API testing in Python.
It started as a small experiment to simplify API debugging and evolved into a full-fledged desktop application.

Key Takeaway:
Even with a simple toolkit like Tkinter, you can create elegant, functional, and professional-grade tools with the right design mindset.
