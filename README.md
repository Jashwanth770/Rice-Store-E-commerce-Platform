# Rice Store E-commerce Platform

## 🍚 Your One-Stop Shop for Premium Rice Varieties

This project is a modern, responsive online e-commerce platform designed for a rice store, providing a seamless Browse and shopping experience. It's built with a focus on intuitive navigation and a clean, visually appealing design, drawing inspiration from leading e-commerce sites like Amazon for its header and footer structure.

---

### ✨ Features

* **Responsive Design:** Adapts fluidly to various screen sizes, ensuring optimal viewing and functionality on desktops, tablets, and mobile devices.
* **Amazon-like Header:** A sophisticated and functional navigation bar featuring:
    * Dynamic Logo
    * Location/Delivery Address display
    * Category-specific search bar with a prominent search icon.
    * Account & Lists, Returns & Orders, and Shopping Cart sections.
    * Secondary navigation panel for quick access to deals, customer service, etc.
* **Amazon-like Footer:** A comprehensive footer with:
    * "Back to Top" functionality.
    * Organized columns for informational links (About Us, Careers, Help, etc.).
    * Bottom section with logo, legal links, and copyright information.
* **Horizontal Image Gallery with Buttons:** A dedicated section to display featured products or categories with images arranged horizontally, each accompanied by a "Shop Now" or "View Details" button.
* **Modular HTML Structure:** Uses Jinja2 templating for efficient and reusable HTML components (e.g., base layout, content blocks).
* **Clean & Modern UI:** Utilizes a carefully chosen color palette (inspired by Amazon) and crisp typography for a professional look.

---

### 🛠️ Tech Stack & Tools

* **Backend:**
    * **Python:** The core programming language.
    * **Flask:** A lightweight and flexible Python web framework used for handling routes, server-side logic, and rendering templates.
* **Frontend:**
    * **HTML5:** For structuring the web content.
    * **CSS3:** For styling the application, including custom layouts with Flexbox and CSS Grid.
    * **Jinja2:** Flask's templating engine, used to embed dynamic content and logic into HTML.
    * **Font Awesome:** A popular icon library for scalable vector icons used in navigation and interactive elements.
* **Development Tools:**
    * **Git:** Version control system for tracking changes.
    * **GitHub:** Platform for hosting the source code repository.
    * **Virtual Environment (`venv`):** Ensures project dependencies are isolated and managed effectively.

---

### 🚀 Installation & Setup (Local)

To get this project up and running on your local machine, follow these steps:

1.  **Clone the Repository:**
    ```bash
    git clone [https://github.com/](https://github.com/)[Your GitHub Username]/Rice-Store-E-commerce-Platform.git
    cd Rice-Store-E-commerce-Platform
    ```

2.  **Create and Activate a Virtual Environment:**
    ```bash
    python -m venv .venv
    # On Windows:
    .\.venv\Scripts\activate
    # On macOS/Linux:
    source ./.venv/bin/activate
    ```

3.  **Install Dependencies:**
    ```bash
    pip install Flask
    # (If you have a requirements.txt from `pip freeze > requirements.txt` later)
    # pip install -r requirements.txt
    ```

4.  **Place Static Assets:**
    * Ensure you have the necessary image files (`amazon_logo.png`, `amazon_logo_white.png`, `image_f87f96.jpg`, `image_f82219.png`, `image_f81a92.png`, `hero_image.jpg`, `laptop.jpg`, `smartwatch.jpg`, `striplight.jpg`, `homerefresh.jpg`, `gaming_accessories.jpg`, `daily_essentials.jpg`, `fashion_trends.jpg`, `toys.jpg`) in the `static/` directory.

5.  **Run the Flask Application:**
    ```bash
    export FLASK_APP=main.py # On macOS/Linux
    set FLASK_APP=main.py   # On Windows
    flask run
    ```
    Alternatively, you can just run:
    ```bash
    python main.py
    ```

6.  **Access the Application:**
    Open your web browser and navigate to `http://127.0.0.1:5000/`.

---

### 💡 Usage

Once the application is running, you can:
* Explore the Amazon-like header and footer, observing their responsiveness.
* View the horizontally arranged product images.
* Interact with the "Shop Now" buttons (though currently placeholders).
* Observe how the layout adapts to different screen sizes.

---

### 🚀 Future Enhancements

* Implement user authentication and user accounts.
* Develop a functional shopping cart and checkout process.
* Add a database (e.g., SQLite, PostgreSQL) for product management.
* Integrate actual product listings and filtering capabilities.
* Introduce dynamic product carousels using JavaScript.
* Enhance search functionality.

---

### 📄 License

This project is open-sourced under the MIT License. (You can choose another license like Apache 2.0 if you prefer).

---

### 📧 Contact

* **JASHWANTHSAI MURARISHETTI**
* **GitHub:** https://github.com/Jashwanth770
* **LinkedIn:** https://www.linkedin.com/in/jashwanthsai-murarishetti/

---
