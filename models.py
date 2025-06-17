from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from flask_login import UserMixin # This should already be there if you used my previous models.py content
# Initialize SQLAlchemy
db = SQLAlchemy()

# User model for authentication and roles
# In models.py
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='customer')
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    phone_number = db.Column(db.String(20), unique=True, nullable=True) # <--- ADD THIS LINE (Unique and nullable as appropriate)
    # Relationships
    orders = db.relationship('Order', backref='customer', lazy=True)
    cart_items = db.relationship('CartItem', backref='user', lazy=True)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.role}', '{self.phone_number}')" # Update __repr__

# Product model
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    stock = db.Column(db.Integer, nullable=False)
    category = db.Column(db.String(50), nullable=False) # e.g., 'Basmati Rice', 'Brown Rice'
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"Product('{self.name}', '{self.price}', '{self.stock}')"

# Order model
class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    order_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    total_amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), nullable=False, default='Pending') # e.g., 'Pending', 'Processing', 'Shipped', 'Delivered', 'Cancelled'
    address = db.Column(db.String(200), nullable=False) # Shipping address

    # Relationship to OrderItem
    items = db.relationship('OrderItem', backref='order', lazy=True)

    def __repr__(self):
        return f"Order('{self.id}', '{self.customer.username}', '{self.total_amount}', '{self.status}')"

# OrderItem model (details of products within an order)
class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False) # Price at the time of order
    # Relationship to Product
    product = db.relationship('Product', lazy=True)

    def __repr__(self):
        return f"OrderItem('{self.order_id}', '{self.product.name}', '{self.quantity}')"

# Cart model - not used directly as a table, instead CartItem links directly to User
# class Cart(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False)
#     items = db.relationship('CartItem', backref='cart', lazy=True, cascade="all, delete-orphan")

# CartItem model (details of products in a user's cart)
class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    # Relationship to Product
    product = db.relationship('Product', lazy=True) # Direct relationship to product

    def __repr__(self):
        return f"CartItem('{self.user_id}', '{self.product.name}', '{self.quantity}')"