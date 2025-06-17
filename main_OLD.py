# import os
# import datetime
# from PIL import Image
# from flask import Flask, render_template, url_for, flash, redirect, request, abort
# from flask_sqlalchemy import SQLAlchemy
# from flask_bcrypt import Bcrypt
# from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
# from flask_uploads import UploadSet, configure_uploads, IMAGES
# import secrets
# from functools import wraps
#
# app = Flask(__name__)
# app.config['SECRET_KEY'] = 'your_super_secret_key'  # Replace with a strong secret key
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
# app.config['UPLOADED_PHOTOS_DEST'] = 'static/product_pics'  # Configure upload folder
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Suppress FSADeprecationWarning
#
# # Make datetime.datetime.utcnow available globally in Jinja2 templates
# app.jinja_env.globals.update(now=datetime.datetime.utcnow)
#
# db = SQLAlchemy(app)
# bcrypt = Bcrypt(app)
# login_manager = LoginManager(app)
# login_manager.login_view = 'login'
# login_manager.login_message_category = 'info'
#
# photos = UploadSet('photos', IMAGES)
# configure_uploads(app, photos)
#
#
# # User loader for Flask-Login
# @login_manager.user_loader
# def load_user(user_id):
#     return User.query.get(int(user_id))
#
#
# # Decorators for role-based access control
# def role_required(*roles):
#     def wrapper(fn):
#         @wraps(fn)
#         def decorated_view(*args, **kwargs):
#             if not current_user.is_authenticated:
#                 flash('Please log in to access this page.', 'info')
#                 return redirect(url_for('login', next=request.url))
#             if current_user.role not in roles:
#                 flash('You do not have permission to access this page.', 'error')
#                 abort(403)  # Forbidden
#             return fn(*args, **kwargs)
#
#         return decorated_view
#
#     return wrapper
#
#
# def admin_required(fn):
#     return role_required('admin')(fn)
#
#
# def sales_representative_required(fn):
#     return role_required('admin', 'sales_representative')(fn)
#
#
# # --- Database Models ---
# class User(db.Model, UserMixin):
#     id = db.Column(db.Integer, primary_key=True)
#     username = db.Column(db.String(20), unique=True, nullable=False)
#     email = db.Column(db.String(120), unique=True, nullable=False)
#     password = db.Column(db.String(60), nullable=False)
#     role = db.Column(db.String(20), nullable=False,
#                      default='customer')  # e.g., 'customer', 'admin', 'sales_representative'
#     products = db.relationship('Product', backref='seller', lazy=True)
#     orders = db.relationship('Order', backref='customer', lazy=True)
#
#     def is_admin(self):
#         return self.role == 'admin'
#
#     def __repr__(self):
#         return f"User('{self.username}', '{self.email}', '{self.role}')"
#
#
# class Product(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     name = db.Column(db.String(100), nullable=False)
#     description = db.Column(db.Text, nullable=False)
#     price = db.Column(db.Float, nullable=False)
#     stock = db.Column(db.Integer, nullable=False)
#     category = db.Column(db.String(50), nullable=False)
#     image_file = db.Column(db.String(20), nullable=False, default='default.jpg')  # Stored filename
#     date_posted = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
#     user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Seller ID
#     order_items = db.relationship('OrderItem', backref='product', lazy=True)  # Link to OrderItems
#
#     def __repr__(self):
#         return f"Product('{self.name}', '{self.price}', '{self.stock}')"
#
#
# class Order(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     customer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
#     order_date = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
#     total_price = db.Column(db.Float, nullable=False)
#     status = db.Column(db.String(20), nullable=False,
#                        default='Pending')  # e.g., 'Pending', 'Processing', 'Shipped', 'Delivered', 'Cancelled'
#     items = db.relationship('OrderItem', backref='order', lazy=True)
#
#     def __repr__(self):
#         return f"Order('{self.id}', '{self.customer_id}', '{self.order_date}', '{self.total_price}', '{self.status}')"
#
#
# class OrderItem(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
#     product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
#     quantity = db.Column(db.Integer, nullable=False)
#     price_at_purchase = db.Column(db.Float, nullable=False)  # Price at the time of purchase
#
#     def __repr__(self):
#         return f"OrderItem('{self.order_id}', '{self.product_id}', '{self.quantity}')"
#
#
# # --- Routes ---
# @app.route("/")
# @app.route("/home")
# def home():
#     products = Product.query.order_by(Product.date_posted.desc()).all()
#     return render_template('index.html', products=products)
#
#
# @app.route("/register", methods=['GET', 'POST'])
# def register():
#     if current_user.is_authenticated:
#         return redirect(url_for('home'))
#     if request.method == 'POST':
#         username = request.form.get('username')
#         email = request.form.get('email')
#         password = request.form.get('password')
#         confirm_password = request.form.get('confirm_password')
#
#         if password != confirm_password:
#             flash('Passwords do not match!', 'error')
#             return redirect(url_for('register'))
#
#         hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
#         new_user = User(username=username, email=email, password=hashed_password, role='customer')  # Default role
#
#         try:
#             db.session.add(new_user)
#             db.session.commit()
#             flash('Your account has been created! You are now able to log in', 'success')
#             return redirect(url_for('login'))
#         except Exception as e:
#             db.session.rollback()
#             flash('Error creating account. Email or Username might already exist.', 'error')
#             return redirect(url_for('register'))
#     return render_template('register.html')
#
#
# @app.route("/login", methods=['GET', 'POST'])
# def login():
#     if current_user.is_authenticated:
#         return redirect(url_for('home'))
#     if request.method == 'POST':
#         email = request.form.get('email')
#         password = request.form.get('password')
#
#         # DEBUG print statements (keep for now if needed, remove later)
#         print(f"DEBUG: Login attempt for email: {email}")
#
#         user = User.query.filter_by(email=email).first()
#
#         if user:
#             print(f"DEBUG: User found: {user.username}, Role: {user.role}")
#             if bcrypt.check_password_hash(user.password, password):
#                 print(f"DEBUG: Password check successful for {user.username}")
#                 login_user(user)
#                 flash('You have been logged in!', 'success')
#                 next_page = request.args.get('next')
#                 return redirect(next_page) if next_page else redirect(url_for('home'))
#             else:
#                 print(f"DEBUG: Password check FAILED for {user.username}")
#                 flash('Login Unsuccessful. Please check email and password', 'error')
#         else:
#             print(f"DEBUG: User with email {email} NOT found in database.")
#             flash('Login Unsuccessful. Please check email and password', 'error')
#     return render_template('login.html')
#
#
# @app.route("/logout")
# @login_required
# def logout():
#     logout_user()
#     flash('You have been logged out.', 'info')
#     return redirect(url_for('home'))
#
#
# @app.route("/account")
# @login_required
# def account():
#     return render_template('account.html', title='My Account')
#
#
# @app.route('/product_detail/<int:product_id>')
# def product_detail(product_id):
#     # Debug print statements (keep these for now if you still need them for 404s)
#     print(f"DEBUG: product_detail route called with ID: {product_id}")
#     print(f"DEBUG: Type of product_id: {type(product_id)}")
#
#     product = Product.query.get(product_id)
#
#     if product:
#         print(f"DEBUG: Product found: {product.name} (ID: {product.id})")
#
#         # NEW CODE FOR RELATED PRODUCTS
#         related_products = Product.query.filter(
#             Product.category == product.category,  # Same category
#             Product.id != product.id  # Exclude the current product
#         ).limit(4).all()
#
#         return render_template('product_detail.html', product=product, related_products=related_products)
#     else:
#         print(f"DEBUG: Product with ID {product_id} NOT found in database.")
#         abort(404)
#
#
# # Updated Search Route to handle category filtering
# @app.route("/search")
# def search():
#     query = request.args.get('query')
#     category = request.args.get('category')
#     products = Product.query
#
#     if query:
#         products = products.filter(
#             (Product.name.like(f'%{query}%')) |
#             (Product.description.like(f'%{query}%'))
#         )
#
#     if category and category != 'All Categories':  # Check if a specific category is selected
#         products = products.filter_by(category=category)
#
#     products = products.order_by(Product.date_posted.desc()).all()
#     return render_template('search_results.html', products=products, query=query, category=category)
#
#
# # --- Admin Routes for Product Management ---
# @app.route("/admin/products")
# @admin_required
# def admin_product_list():
#     products = Product.query.all()
#     return render_template('admin_product_list.html', products=products)
#
#
# @app.route("/admin/product/add", methods=['GET', 'POST'])
# @admin_required
# def add_product_admin():
#     if request.method == 'POST':
#         name = request.form.get('name')
#         description = request.form.get('description')
#         price = float(request.form.get('price'))
#         stock = int(request.form.get('stock'))
#         category = request.form.get('category')
#         image_file = 'default.jpg'  # Default image if none uploaded
#
#         # Handle image upload if available
#         if 'image' in request.files and request.files['image'].filename != '':
#             try:
#                 # Save the uploaded image
#                 # Generate a random 8-character hex string for the filename
#                 random_hex = secrets.token_hex(4)
#                 # Get file extension from the original filename
#                 _, f_ext = os.path.splitext(request.files['image'].filename)
#                 # Combine random string with original extension
#                 picture_fn = random_hex + f_ext
#                 picture_path = os.path.join(app.root_path, 'static/product_pics', picture_fn)
#
#                 # Resize image before saving
#                 output_size = (400, 400)  # Example size
#                 i = Image.open(request.files['image'])
#                 i.thumbnail(output_size)
#                 i.save(picture_path)
#
#                 image_file = picture_fn
#             except Exception as e:
#                 flash(f'Image upload failed: {e}', 'error')
#                 return redirect(url_for('add_product_admin'))
#
#         new_product = Product(
#             name=name,
#             description=description,
#             price=price,
#             stock=stock,
#             category=category,
#             image_file=image_file,
#             user_id=current_user.id  # Assign to the current admin user
#         )
#
#         try:
#             db.session.add(new_product)
#             db.session.commit()
#             flash(f'Product "{name}" added successfully!', 'success')
#             return redirect(url_for('admin_product_list'))
#         except Exception as e:
#             db.session.rollback()
#             flash(f'Error adding product: {e}', 'error')
#             return redirect(url_for('add_product_admin'))
#     return render_template('admin_add_product.html')
#
#
# @app.route("/admin/product/edit/<int:product_id>", methods=['GET', 'POST'])
# @admin_required
# def edit_product_admin(product_id):
#     product = Product.query.get_or_404(product_id)
#     if request.method == 'POST':
#         product.name = request.form.get('name')
#         product.description = request.form.get('description')
#         product.price = float(request.form.get('price'))
#         product.stock = int(request.form.get('stock'))
#         product.category = request.form.get('category')
#
#         if 'image' in request.files and request.files['image'].filename != '':
#             try:
#                 # Delete old image if it's not the default one
#                 if product.image_file and product.image_file != 'default.jpg':
#                     old_image_path = os.path.join(app.config['UPLOADED_PHOTOS_DEST'], product.image_file)
#                     if os.path.exists(old_image_path):
#                         os.remove(old_image_path)
#
#                 # Save new image
#                 random_hex = secrets.token_hex(4)
#                 _, f_ext = os.path.splitext(request.files['image'].filename)
#                 picture_fn = random_hex + f_ext
#                 picture_path = os.path.join(app.root_path, 'static/product_pics', picture_fn)
#
#                 output_size = (400, 400)
#                 i = Image.open(request.files['image'])
#                 i.thumbnail(output_size)
#                 i.save(picture_path)
#
#                 product.image_file = picture_fn
#             except Exception as e:
#                 flash(f'Image upload failed during edit: {e}', 'error')
#                 # Don't return here, just proceed with other updates
#
#         try:
#             db.session.commit()
#             flash(f'Product "{product.name}" updated successfully!', 'success')
#             return redirect(url_for('admin_product_list'))
#         except Exception as e:
#             db.session.rollback()
#             flash(f'Error updating product: {e}', 'error')
#             return redirect(url_for('edit_product_admin', product_id=product.id))
#     return render_template('admin_edit_product.html', product=product)
#
#
# @app.route("/admin/product/delete/<int:product_id>", methods=['POST'])
# @admin_required
# def delete_product_admin(product_id):
#     product = Product.query.get_or_404(product_id)
#     try:
#         # Delete image file if not default
#         if product.image_file and product.image_file != 'default.jpg':
#             image_path = os.path.join(app.config['UPLOADED_PHOTOS_DEST'], product.image_file)
#             if os.path.exists(image_path):
#                 os.remove(image_path)
#
#         db.session.delete(product)
#         db.session.commit()
#         flash(f'Product "{product.name}" deleted successfully!', 'success')
#     except Exception as e:
#         db.session.rollback()
#         flash(f'Error deleting product: {e}', 'error')
#     return redirect(url_for('admin_product_list'))
#
#
# # --- Admin Routes for User Management ---
# @app.route("/admin/users")
# @admin_required
# def admin_user_management():
#     users = User.query.all()
#     return render_template('admin_user_management.html', users=users)
#
#
# @app.route("/admin/user/edit_role/<int:user_id>", methods=['POST'])
# @admin_required
# def edit_user_role(user_id):
#     user = User.query.get_or_404(user_id)
#     new_role = request.form.get('role')
#     # Define your allowed roles and ensure admin cannot demote themselves accidentally
#     if new_role in ['customer', 'admin', 'sales_representative']:
#         user.role = new_role
#         db.session.commit()
#         flash(f'Role for user {user.username} updated to {new_role}', 'success')
#     else:
#         flash('Invalid role provided.', 'error')
#     return redirect(url_for('admin_user_management'))
#
#
# @app.route("/admin/user/delete/<int:user_id>", methods=['POST'])
# @admin_required
# def delete_user_admin(user_id):
#     user = User.query.get_or_404(user_id)
#     # Prevent admin from deleting themselves
#     if user.id == current_user.id:
#         flash("You cannot delete your own admin account!", 'error')
#         return redirect(url_for('admin_user_management'))
#
#     try:
#         db.session.delete(user)
#         db.session.commit()
#         flash(f'User "{user.username}" deleted successfully!', 'success')
#     except Exception as e:
#         db.session.rollback()
#         flash(f'Error deleting user: {e}', 'error')
#     return redirect(url_for('admin_user_management'))
#
#
# # --- Admin/Sales Representative Routes for Order Management ---
# @app.route("/admin/orders")
# @sales_representative_required
# def admin_order_list():
#     orders = Order.query.order_by(Order.order_date.desc()).all()
#     return render_template('admin_order_list.html', orders=orders)
#
#
# @app.route("/admin/order/update_status/<int:order_id>", methods=['POST'])
# @sales_representative_required
# def update_order_status(order_id):
#     order = Order.query.get_or_404(order_id)
#     new_status = request.form.get('status')
#     if new_status:
#         order.status = new_status
#         db.session.commit()
#         flash(f'Order {order.id} status updated to {new_status}', 'success')
#     return redirect(url_for('admin_order_list'))
#
#
# if __name__ == '__main__':
#     with app.app_context():
#         db.create_all()
#         # Create a default admin user if one doesn't exist
#         if not User.query.filter_by(email='admin@example.com').first():
#             hashed_password = bcrypt.generate_password_hash('adminpassword').decode('utf-8')
#             admin_user = User(username='admin', email='admin@example.com', password=hashed_password, role='admin')
#             db.session.add(admin_user)
#             db.session.commit()
#             print("Default admin user created!")
#         print("Database initialized.")
#     app
#     .run(debug=True)


0d29442aa16074a259ab6d3badc7fb3d