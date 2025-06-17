# ... (Keep all existing imports, configurations, models, and previous routes up to add_product_admin) ...
from dotenv import load_dotenv
import os
from flask_pymongo import PyMongo
app = Flask(__name__)
load_dotenv()
app.config["MONGO_URI"] = os.getenv("MONGO_URI")  # ensure .env has this key
mongo = PyMongo(app)

# --- Admin Product List Route ---
@app.route('/admin/products')
@login_required
def admin_product_list():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('home'))

    products = Product.query.all()
    return render_template('admin_product_list.html', products=products)


# --- Admin Edit Product Route ---
@app.route('/admin/edit_product/<int:product_id>', methods=['GET', 'POST'])
@login_required
def edit_product_admin(product_id):
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('home'))

    product = Product.query.get_or_404(product_id)

    if request.method == 'POST':
        product.name = request.form['name']
        product.description = request.form['description']

        # Handle price and stock validation
        try:
            product.price = float(request.form['price'])
            product.stock = int(request.form['stock'])
            if product.price <= 0 or product.stock < 0:
                flash('Price must be positive and Stock cannot be negative.', 'danger')
                return render_template('edit_product.html', product=product)
        except ValueError:
            flash('Invalid input for price or stock. Please enter numbers.', 'danger')
            return render_template('edit_product.html', product=product)

        # Handle image upload (similar to add_product)
        if 'image' in request.files:
            file = request.files['image']
            if file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                product.image_file = filename
            elif file.filename != '':  # User selected a file but it's not allowed
                flash('Invalid image file type. Allowed: png, jpg, jpeg, gif.', 'warning')
                return render_template('edit_product.html', product=product)

        db.session.commit()
        flash(f'Product "{product.name}" updated successfully!', 'success')
        return redirect(url_for('admin_product_list'))  # Redirect to admin list after edit

    return render_template('edit_product.html', product=product)


# --- Admin Delete Product Route ---
@app.route('/admin/delete_product/<int:product_id>', methods=['POST'])
@login_required
def delete_product_admin(product_id):
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('home'))

    product = Product.query.get_or_404(product_id)

    # Check if product is part of any existing order items (optional, but good practice)
    if product.order_items:
        flash(
            f'Cannot delete "{product.name}" because it is part of existing orders. Consider setting stock to 0 instead.',
            'danger')
        return redirect(url_for('admin_product_list'))

    db.session.delete(product)
    db.session.commit()
    flash(f'Product "{product.name}" deleted successfully!', 'success')
    return redirect(url_for('admin_product_list'))

# ... (Keep all existing cart functions, checkout, order history, invoice routes, and run app block) ...