import os
import secrets
from PIL import Image
from datetime import datetime
from flask import Flask, render_template, url_for, flash, redirect, request, abort, current_app, make_response, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from flask_moment import Moment  # Make sure this is here!
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, DecimalField, IntegerField, \
    SelectField, RadioField  # Added RadioField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, NumberRange
from flask_mail import Mail, Message

from functools import wraps
import pdfkit

# --- Flask App Configuration ---
app = Flask(__name__)
# IMPORTANT: Change 'your_super_secret_key_here_CHANGE_THIS' to a strong, unique secret key for production.
# Consider using an environment variable in a real application.
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_very_secret_key_that_you_should_change_for_production_12345')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static')  # Base static folder
app.config['PRODUCT_PICS_FOLDER'] = os.path.join(app.static_folder, 'product_pics')
app.config['PROFILE_PICS_FOLDER'] = os.path.join(app.static_folder, 'profile_pics')
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript from accessing cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Prevent most CSRF attacks

# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # or your SMTP server
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_admin_email@gmail.com'  # CHANGE THIS
app.config['MAIL_PASSWORD'] = 'your_email_password_or_app_password'  # CHANGE THIS
app.config['MAIL_DEFAULT_SENDER'] = 'your_admin_email@gmail.com'  # CHANGE THIS

# Ensure upload folders exist
os.makedirs(app.config['PRODUCT_PICS_FOLDER'], exist_ok=True)
os.makedirs(app.config['PROFILE_PICS_FOLDER'], exist_ok=True)

# --- Extensions Initialization ---
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Route name for login page
login_manager.login_message_category = 'info'
moment = Moment(app)  # Initialize Flask-Moment
mail = Mail(app)



# --- User Loader for Flask-Login ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# --- Custom Decorator for Admin Access ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            abort(403)  # Forbidden
        return f(*args, **kwargs)

    return decorated_function


# --- Models (Typically in models.py) ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(10), nullable=False, default='user')  # 'user' or 'admin'
    cart_items = db.relationship('CartItem', backref='owner', lazy=True)
    orders = db.relationship('Order', backref='customer', lazy=True)
    phone_number = db.Column(db.String(20), nullable=True)  # Added for demonstration if not already there

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.image_file}', '{self.role}')"


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    stock = db.Column(db.Integer, nullable=False, default=0)
    image_file = db.Column(db.String(20), nullable=False, default='default_product.png')
    category = db.Column(db.String(50), nullable=True)  # e.g., Basmati, Sona Masuri, Brown Rice
    cart_item_rel = db.relationship('CartItem', backref='product', lazy=True)
    order_item_rel = db.relationship('OrderItem', backref='product', lazy=True)

    def __repr__(self):
        return f"Product('{self.name}', '{self.price}', '{self.stock}')"


class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)

    def __repr__(self):
        return f"CartItem(User:{self.user_id}, Product:{self.product_id}, Qty:{self.quantity})"


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    order_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    total_amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), nullable=False, default='Pending')  # e.g., Pending, Shipped, Delivered, Cancelled
    address = db.Column(db.String(200), nullable=False, default='Default Address')  # Added address field with default value
    order_items = db.relationship('OrderItem', backref='order', lazy=True)

    def __repr__(self):
        return f"Order('{self.id}', 'User:{self.user_id}', 'Total:{self.total_amount}', 'Status:{self.status}')"


class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price_at_purchase = db.Column(db.Float, nullable=False)  # Price at the time of order

    def __repr__(self):
        return f"OrderItem(Order:{self.order_id}, Product:{self.product_id}, Qty:{self.quantity})"


# --- Forms (Typically in forms.py) ---
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone_number = StringField('Phone Number', validators=[Length(max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is taken. Please choose a different one.')


class LoginForm(FlaskForm):
    email_or_phone = StringField('Email or Phone Number', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


class UpdateAccountForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    picture = FileField('Update Profile Picture', validators=[FileAllowed(['jpg', 'png', 'jpeg'])])
    phone_number = StringField('Phone Number', validators=[Length(max=20)])
    submit = SubmitField('Update')

    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('That email is taken. Please choose a different one.')


class ProductForm(FlaskForm):
    name = StringField('Product Name', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Description', validators=[DataRequired()])
    price = DecimalField('Price', validators=[DataRequired(), NumberRange(min=0.01)])
    stock = IntegerField('Stock Quantity', validators=[DataRequired(), NumberRange(min=0)])
    image = FileField('Product Image', validators=[FileAllowed(['jpg', 'png', 'jpeg'])])
    category = StringField('Category', validators=[Length(max=50)])
    submit = SubmitField('Add Product')


class PaymentForm(FlaskForm):
    payment_method = RadioField('Payment Method',
                                choices=[('cod', 'Cash on Delivery'),
                                         ('online', 'Online Payment')],
                                validators=[DataRequired()])
    address = TextAreaField('Delivery Address', validators=[DataRequired(), Length(min=10, max=200)])
    submit = SubmitField('Confirm Order')


# --- Helper Functions ---
def save_picture(form_picture, folder_name='profile_pics'):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext

    if folder_name == 'profile_pics':
        output_size = (125, 125)
        picture_path = os.path.join(app.config['PROFILE_PICS_FOLDER'], picture_fn)
    elif folder_name == 'product_pics':
        output_size = (300, 300)  # Or a suitable size for products
        picture_path = os.path.join(app.config['PRODUCT_PICS_FOLDER'], picture_fn)
    else:
        raise ValueError("Invalid folder_name specified for saving picture.")

    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)
    return picture_fn




# --- Jinja2 Context Processor for global data ---
@app.context_processor
def inject_global_data():
    return dict(current_year=datetime.utcnow().year)



# --- Routes ---

@app.route("/")
@app.route("/home")
def home():
    query = request.args.get('q')
    if query:
        products = Product.query.filter(Product.name.ilike(f'%{query}%')).all()
    else:
        products = Product.query.all()
    return render_template('home.html', products=products)


@app.route("/products")
def products():
    products = Product.query.all()
    return render_template('products.html', products=products, title='All Products')


@app.route("/product/<int:product_id>")
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template('product_detail.html', title=product.name, product=product)


@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        identifier = form.email_or_phone.data
        # Check if identifier is an email or phone number
        if '@' in identifier:
            user = User.query.filter_by(email=identifier).first()
        else:
            user = User.query.filter_by(phone_number=identifier).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            flash(f'Welcome, {user.username}!', 'success')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check your credentials.', 'danger')
    return render_template('login.html', title='Login', form=form)


@app.route("/logout")
def logout():
    print("Logout route called")  # Debug
    logout_user()
    session.clear()  # Force clear all session data
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data, folder_name='profile_pics')
            current_user.image_file = picture_file
        current_user.username = form.username.data
        current_user.email = form.email.data
        current_user.phone_number = form.phone_number.data
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
        form.phone_number.data = current_user.phone_number
    image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    return render_template('account.html', title='Account', image_file=image_file, form=form)


@app.route("/add_to_cart/<int:product_id>", methods=['POST'])
@login_required
def add_to_cart(product_id):
    product = Product.query.get_or_404(product_id)
    quantity = request.form.get('quantity', 1, type=int)

    if quantity <= 0:
        flash('Quantity must be at least 1.', 'danger')
        return redirect(url_for('product_detail', product_id=product.id))

    if product.stock < quantity:
        flash(f'Not enough stock for {product.name}. Available: {product.stock}', 'danger')
        return redirect(url_for('product_detail', product_id=product.id))

    cart_item = CartItem.query.filter_by(user_id=current_user.id, product_id=product.id).first()
    if cart_item:
        if product.stock < (cart_item.quantity + quantity):
            flash(f'Adding more would exceed stock for {product.name}. Available: {product.stock - cart_item.quantity}',
                  'danger')
            return redirect(url_for('product_detail', product_id=product.id))
        cart_item.quantity += quantity
    else:
        cart_item = CartItem(user_id=current_user.id, product_id=product.id, quantity=quantity)
        db.session.add(cart_item)
    db.session.commit()
    flash(f'{quantity} x {product.name} added to cart!', 'success')
    return redirect(url_for('cart'))


@app.route("/cart")
@login_required
def cart():
    cart_items = CartItem.query.filter_by(user_id=current_user.id).all()
    total_price = sum(item.product.price * item.quantity for item in cart_items if item.product)
    return render_template('cart.html', cart_items=cart_items, total_price=total_price)


@app.route("/cart/update/<int:item_id>", methods=['POST'])
@login_required
def update_cart_item(item_id):
    item = CartItem.query.get_or_404(item_id)
    if item.user_id != current_user.id:
        abort(403)  # Forbidden

    new_quantity = request.form.get('quantity', type=int)
    if new_quantity is None or new_quantity <= 0:
        flash('Quantity must be a positive number.', 'danger')
        return redirect(url_for('cart'))

    if item.product.stock < new_quantity:
        flash(f'Cannot update. Only {item.product.stock} of {item.product.name} are available.', 'danger')
        return redirect(url_for('cart'))

    item.quantity = new_quantity
    db.session.commit()
    flash('Cart item quantity updated!', 'success')
    return redirect(url_for('cart'))


@app.route("/cart/remove/<int:item_id>", methods=['POST'])
@login_required
def remove_from_cart(item_id):
    item = CartItem.query.get_or_404(item_id)
    if item.user_id != current_user.id:
        abort(403)  # Forbidden
    db.session.delete(item)
    db.session.commit()
    return redirect(url_for('cart'))


# New route for Checkout Summary & Payment Method Selection
@app.route("/checkout_summary", methods=['GET', 'POST'])
@login_required
def checkout_summary():
    cart_items = CartItem.query.filter_by(user_id=current_user.id).all()
    if not cart_items:
        flash('Your cart is empty!', 'danger')
        return redirect(url_for('cart'))

    total_price = sum(item.product.price * item.quantity for item in cart_items if item.product)
    form = PaymentForm()

    if form.validate_on_submit():
        payment_method = form.payment_method.data
        address = form.address.data
        # Pass address as a query parameter
        return redirect(url_for('place_order', payment_method=payment_method, address=address))

    return render_template('checkout_summary.html',
                         title='Checkout Summary',
                         cart_items=cart_items,
                         total_price=total_price,
                         form=form,
                         now=datetime.utcnow)


# Updated route for final order placement (was previously just '/checkout')
@app.route("/place_order/<string:payment_method>", methods=['GET', 'POST'])
@login_required
def place_order(payment_method):
    address = request.args.get('address') or request.form.get('address')
    cart_items = CartItem.query.filter_by(user_id=current_user.id).all()
    if not cart_items:
        flash('Your cart is empty!', 'danger')
        return redirect(url_for('cart'))

    # Check stock for all items before placing order
    for item in cart_items:
        if item.quantity > item.product.stock:
            flash(f'Not enough stock for {item.product.name}. Please adjust quantity in cart.', 'danger')
            return redirect(url_for('cart'))

    new_order = Order(user_id=current_user.id, total_amount=0, address=address)  # Save address
    db.session.add(new_order)
    db.session.flush()  # Get the order ID before committing order items

    total_amount = 0
    for item in cart_items:
        order_item = OrderItem(
            order_id=new_order.id,
            product_id=item.product.id,
            quantity=item.quantity,
            price_at_purchase=item.product.price
        )
        db.session.add(order_item)
        item.product.stock -= item.quantity  # Reduce stock
        total_amount += (item.product.price * item.quantity)
        db.session.delete(item)  # Remove from cart

    new_order.total_amount = total_amount

    if payment_method == 'cod':
        new_order.status = 'Pending COD'
        flash('Your order has been placed successfully via Cash on Delivery!', 'success')
    elif payment_method == 'online':
        new_order.status = 'Payment Pending'
        flash('Your order has been placed. Please complete the online payment (feature not fully implemented).', 'success')

    db.session.commit()

    # Send email to admin
    try:
        admin_email = 'your_admin_email@gmail.com'  # CHANGE THIS
        msg = Message(
            subject=f"New Order Placed: Order #{new_order.id}",
            recipients=[admin_email],
            body=f"A new order has been placed by {current_user.username} (User ID: {current_user.id}).\n"
                 f"Order ID: {new_order.id}\n"
                 f"Total Amount: ₹{new_order.total_amount}\n"
                 f"Status: {new_order.status}\n"
                 f"Address: {new_order.address}\n"
                 f"Date: {new_order.order_date}\n"
                 f"Check the admin dashboard for more details."
        )
        mail.send(msg)
    except Exception as e:
        print(f"Failed to send admin email: {e}")

    return redirect(url_for('invoice', order_id=new_order.id))


@app.route("/orders")
@login_required
def orders():
    user_orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.order_date.desc()).all()
    return render_template('orders.html', orders=user_orders, title='My Orders')


@app.route("/order/<int:order_id>")
@login_required
def order_detail(order_id):
    order = Order.query.get_or_404(order_id)
    if order.user_id != current_user.id and current_user.role != 'admin':
        abort(403)  # Forbidden
    return render_template('order_detail.html', order=order, title=f'Order #{order.id}')


@app.route('/invoice/<int:order_id>')
@login_required
def invoice(order_id):
    order = Order.query.get_or_404(order_id)
    if order.user_id != current_user.id and current_user.role != 'admin':
        abort(403)
    return render_template('invoice.html', order=order, title=f'Invoice #{order.id}')


@app.route('/invoice/<int:order_id>/download')
@login_required
def download_invoice(order_id):
    order = Order.query.get_or_404(order_id)
    if order.user_id != current_user.id and current_user.role != 'admin':
        abort(403)
    rendered = render_template('invoice_pdf.html', order=order)
    pdf = pdfkit.from_string(rendered, False)
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=invoice_{order.id}.pdf'
    return response


# --- Admin Routes ---

@app.route("/admin/dashboard")
@login_required
@admin_required
def admin_dashboard():
    total_users = User.query.count()
    total_products = Product.query.count()
    total_orders = Order.query.count()
    pending_orders = Order.query.filter_by(status='Pending').count()
    return render_template('admin/dashboard.html', title='Admin Dashboard',
                           total_users=total_users, total_products=total_products,
                           total_orders=total_orders, pending_orders=pending_orders)


@app.route("/admin/products")
@login_required
@admin_required
def admin_products():
    products = Product.query.all()
    return render_template('admin/products.html', title='Manage Products', products=products)


@app.route("/admin/product/new", methods=['GET', 'POST'])
@login_required
@admin_required
def admin_add_product():
    form = ProductForm()
    if form.validate_on_submit():
        image_file = 'default_product.png'
        if form.image.data:
            image_file = save_picture(form.image.data, folder_name='product_pics')

        product = Product(
            name=form.name.data,
            description=form.description.data,
            price=form.price.data,
            stock=form.stock.data,
            image_file=image_file,
            category=form.category.data
        )
        db.session.add(product)
        db.session.commit()
        flash('Product has been added!', 'success')
        return redirect(url_for('admin_products'))
    return render_template('admin/add_product.html', title='Add New Product', form=form, legend='Add Product')


@app.route("/admin/product/<int:product_id>/update", methods=['GET', 'POST'])
@login_required
@admin_required
def admin_update_product(product_id):
    product = Product.query.get_or_404(product_id)
    form = ProductForm()
    if form.validate_on_submit():
        if form.image.data:
            picture_file = save_picture(form.image.data, folder_name='product_pics')
            product.image_file = picture_file
        product.name = form.name.data
        product.description = form.description.data
        product.price = form.price.data
        product.stock = form.stock.data
        product.category = form.category.data
        db.session.commit()
        flash('Product has been updated!', 'success')
        return redirect(url_for('admin_products'))
    elif request.method == 'GET':
        form.name.data = product.name
        form.description.data = product.description
        form.price.data = product.price
        form.stock.data = product.stock
        form.category.data = product.category
    image_file = url_for('static', filename='product_pics/' + product.image_file)
    return render_template('admin/add_product.html', title='Update Product',
                           form=form, legend='Update Product', image_file=image_file)


@app.route("/admin/product/<int:product_id>/delete", methods=['POST'])
@login_required
@admin_required
def admin_delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    CartItem.query.filter_by(product_id=product.id).delete()
    OrderItem.query.filter_by(product_id=product.id).delete()
    db.session.delete(product)
    db.session.commit()
    flash('Product has been deleted!', 'success')
    return redirect(url_for('admin_products'))


@app.route("/admin/users")
@login_required
@admin_required
def admin_users():
    users = User.query.all()
    return render_template('admin/users.html', title='Manage Users', users=users)


@app.route("/admin/user/<int:user_id>/delete", methods=['POST'])
@login_required
@admin_required
def admin_delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("You cannot delete your own admin account!", 'danger')
        return redirect(url_for('admin_users'))

    CartItem.query.filter_by(user_id=user.id).delete()
    orders = Order.query.filter_by(user_id=user.id).all()
    for order in orders:
        OrderItem.query.filter_by(order_id=order.id).delete()
    Order.query.filter_by(user_id=user.id).delete()

    db.session.delete(user)
    db.session.commit()
    flash('User has been deleted!', 'success')
    return redirect(url_for('admin_users'))


@app.route("/admin/orders")
@login_required
@admin_required
def admin_orders():
    all_orders = Order.query.order_by(Order.order_date.desc()).all()
    return render_template('admin/orders.html', title='Manage All Orders', orders=all_orders)


@app.route("/admin/search_invoices", methods=['GET'])
@login_required
@admin_required
def admin_search_invoices():
    query = request.args.get('query', '')
    if query:
        # Search orders by ID or customer name
        orders = Order.query.join(User).filter(
            (Order.id.like(f'%{query}%')) |
            (User.username.like(f'%{query}%'))
        ).order_by(Order.order_date.desc()).all()
    else:
        orders = Order.query.order_by(Order.order_date.desc()).all()
    return render_template('admin/orders.html', title='Search Results', orders=orders, query=query)


@app.route("/admin/order/<int:order_id>/update_status", methods=['POST'])
@login_required
@admin_required
def admin_update_order_status(order_id):
    order = Order.query.get_or_404(order_id)
    new_status = request.form.get('status')
    if new_status in ['Pending', 'Pending COD', 'Payment Pending', 'Shipped', 'Delivered', 'Cancelled']:
        order.status = new_status
        db.session.commit()
        flash(f'Order #{order.id} status updated to {new_status}', 'success')
    else:
        flash('Invalid status', 'danger')
    return redirect(url_for('admin_orders'))


# --- Database Creation and Initial Data ---
def create_tables():
    with app.app_context():
        db.create_all()  # This creates the database and tables
        # Create an admin user if not exists
        if not User.query.filter_by(username='admin').first():
            hashed_password = bcrypt.generate_password_hash('adminpassword').decode('utf-8')
            admin_user = User(username='admin', email='admin@example.com', password=hashed_password, role='admin')
            db.session.add(admin_user)
            db.session.commit()
            print("Admin user created: username='admin', password='adminpassword'")

        # Create a sample product if not exists
        if not Product.query.filter_by(name='Basmati Rice').first():
            sample_product = Product(
                name='Basmati Rice',
                description='Premium extra-long grain aromatic Basmati rice, perfect for biryanis and pilafs.',
                price=150.00,
                stock=100,
                image_file='basmati_rice.png',  # Ensure you have this in static/product_pics
                category='Basmati'
            )
            db.session.add(sample_product)
            db.session.commit()
            print("Sample product 'Basmati Rice' added.")

        # Create a regular user if not exists
        if not User.query.filter_by(username='testuser').first():
            hashed_password = bcrypt.generate_password_hash('password').decode('utf-8')
            test_user = User(username='testuser', email='test@example.com', password=hashed_password, role='user')
            db.session.add(test_user)
            db.session.commit()
            print("Test user created: username='testuser', password='password'")


if __name__ == '__main__':

    with app.app_context():
        db.create_all()  # Ensure tables exist first
        create_tables()  # Then populate initial data
    app.run(debug=True)