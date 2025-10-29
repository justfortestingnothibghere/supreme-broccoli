import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort, Response
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash
import cloudinary
import cloudinary.uploader
import cloudinary.utils
from sqlalchemy import func
from io import StringIO
import csv
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'devkey')
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024  # 200MB max

# Database setup
db_uri = os.getenv('DATABASE_URL')
if db_uri and db_uri.startswith('postgres://'):
    db_uri = db_uri.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = db_uri or 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Login Manager
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Cloudinary setup
cloudinary.config(
    cloud_name=os.getenv('CLOUDINARY_CLOUD_NAME'),
    api_key=os.getenv('CLOUDINARY_API_KEY'),
    api_secret=os.getenv('CLOUDINARY_API_SECRET'),
    secure=True
)

# ==================== MODELS ====================
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    phone = db.Column(db.String(20))
    channel_name = db.Column(db.String(100), unique=True)
    channel_bio = db.Column(db.Text)
    profile_photo = db.Column(db.String(500))
    role = db.Column(db.String(20), default='user')  # user, creator_pending, creator, admin
    banned = db.Column(db.Boolean, default=False)
    verified = db.Column(db.Boolean, default=False)
    subscribers_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Flask-Login required methods
    def is_active(self):
        return not self.banned

    def is_authenticated(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

class Video(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    video_url = db.Column(db.String(500), nullable=False)
    thumbnail_url = db.Column(db.String(500), nullable=False)
    category = db.Column(db.String(50), default='General')
    uploader_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    views = db.Column(db.Integer, default=0)
    approved = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    video_id = db.Column(db.Integer, db.ForeignKey('video.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    text = db.Column(db.Text, nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('comment.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    target_type = db.Column(db.String(20), nullable=False)
    target_id = db.Column(db.Integer, nullable=False)
    value = db.Column(db.Integer, default=1)
    __table_args__ = (db.UniqueConstraint('user_id', 'target_type', 'target_id', name='unique_like'),)

class Subscription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    channel_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    __table_args__ = (db.UniqueConstraint('user_id', 'channel_id', name='unique_sub'),)

class Verification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False)
    instagram = db.Column(db.String(200))
    youtube = db.Column(db.String(200))
    pan_number = db.Column(db.String(50))
    pan_photo = db.Column(db.String(500))
    reason = db.Column(db.Text)
    status = db.Column(db.String(20), default='pending')
    rejection_message = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    category = db.Column(db.String(50))
    known_as = db.Column(db.String(100))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ==================== FORMS ====================
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Register')

class CreatorRegisterForm(RegisterForm):
    phone = StringField('Phone', validators=[DataRequired()])
    channel_name = StringField('Channel Name', validators=[DataRequired()])
    channel_bio = TextAreaField('Channel Bio')
    profile_public_id = StringField('Profile Photo Public ID')

class BlueTickForm(FlaskForm):
    instagram = StringField('Instagram URL')
    youtube = StringField('YouTube URL')
    pan_number = StringField('PAN Number', validators=[DataRequired()])
    pan_public_id = StringField('PAN Photo Public ID')
    reason = TextAreaField('Why Blue Tick?', validators=[DataRequired()])
    submit = SubmitField('Submit')
    known_as = StringField('Known As (optional)')
    category = SelectField('Category', choices=[('News/Media', 'News/Media'), ('Sports', 'Sports'), ('Government/Politics', 'Government/Politics'), ('Music', 'Music'), ('Fashion', 'Fashion'), ('Entertainment', 'Entertainment'), ('Blogger/Influencer', 'Blogger/Influencer'), ('Business/Brand/Organization', 'Business/Brand/Organization'), ('Other', 'Other')])

class VideoForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    description = TextAreaField('Description')
    category = SelectField('Category', choices=[
        ('General', 'General'), ('Music', 'Music'), ('Gaming', 'Gaming'),
        ('Vlogs', 'Vlogs'), ('Education', 'Education')
    ])
    public_id = StringField('Video Public ID', validators=[DataRequired()])
    submit = SubmitField('Upload Video')

# ==================== CREATE TABLES ====================
with app.app_context():
    db.create_all()

# ==================== ROUTES ====================
@app.route('/')
def index():
    page = request.args.get('page', 1, type=int)
    q = request.args.get('q', '')
    category = request.args.get('category', '')
    videos_query = Video.query.filter_by(approved=True)
    if q:
        videos_query = videos_query.filter((Video.title.ilike(f'%{q}%')) | (Video.description.ilike(f'%{q}%')))
    if category:
        videos_query = videos_query.filter_by(category=category)
    videos = videos_query.order_by(Video.views.desc()).paginate(page=page, per_page=12)
    categories = [c[0] for c in db.session.query(Video.category.distinct()).filter(Video.approved==True).all()]
    return render_template('index.html', videos=videos, categories=categories, q=q, category=category)

@app.route('/feed')
@login_required
def feed():
    subs = [s.channel_id for s in Subscription.query.filter_by(user_id=current_user.id).all()]
    page = request.args.get('page', 1, type=int)
    videos = Video.query.filter(Video.uploader_id.in_(subs or [0]), Video.approved==True).order_by(Video.created_at.desc()).paginate(page=page, per_page=12)
    return render_template('feed.html', videos=videos)

@app.route('/channel/<int:user_id>')
def channel(user_id):
    channel = User.query.get_or_404(user_id)
    videos = Video.query.filter_by(uploader_id=user_id, approved=True).order_by(Video.created_at.desc()).all()
    is_subbed = bool(Subscription.query.filter_by(user_id=current_user.id if current_user.is_authenticated else 0, channel_id=user_id).first())
    is_own = current_user.is_authenticated and current_user.id == user_id
    if is_own:
        total_views = sum(v.views for v in videos)
        total_likes = db.session.query(func.sum(Like.value)).filter(Like.target_type=='video', Like.target_id.in_([v.id for v in videos])).scalar() or 0
    else:
        total_views = total_likes = None
    return render_template('channel.html', channel=channel, videos=videos, is_subbed=is_subbed, is_own=is_own, total_views=total_views, total_likes=total_likes, subs=channel.subscribers_count)

@app.route('/video/<int:video_id>')
def watch(video_id):
    video = Video.query.filter_by(id=video_id, approved=True).first_or_404()
    video.views += 1
    db.session.commit()
    comments = Comment.query.filter_by(video_id=video_id).order_by(Comment.created_at.asc()).all()
    likes_count = db.session.query(func.sum(Like.value)).filter_by(target_type='video', target_id=video_id).scalar() or 0
    user_like = Like.query.filter_by(user_id=current_user.id if current_user.is_authenticated else 0, target_type='video', target_id=video_id).first()
    user_like_val = user_like.value if user_like else 0
    related = Video.query.filter(Video.id != video_id, Video.approved==True, (Video.category == video.category) | (Video.uploader_id == video.uploader_id)).order_by(func.random()).limit(6).all()
    embed_url = url_for('watch', video_id=video_id, _external=True)
    return render_template('watch.html', video=video, comments=comments, likes_count=likes_count, user_like_val=user_like_val, related=related, embed_url=embed_url)

# API
@app.route('/api/like/<target_type>/<int:target_id>', methods=['POST'])
@login_required
def api_like(target_type, target_id):
    like = Like.query.filter_by(user_id=current_user.id, target_type=target_type, target_id=target_id).first()
    if like:
        if like.value == 1:
            db.session.delete(like)
            val = 0
        else:
            like.value = 1
            val = 1
    else:
        like = Like(user_id=current_user.id, target_type=target_type, target_id=target_id, value=1)
        db.session.add(like)
        val = 1
    db.session.commit()
    count = db.session.query(func.sum(Like.value)).filter_by(target_type=target_type, target_id=target_id).scalar() or 0
    return jsonify(count=count, val=val)

@app.route('/api/unlike/<target_type>/<int:target_id>', methods=['POST'])
@login_required
def api_unlike(target_type, target_id):
    like = Like.query.filter_by(user_id=current_user.id, target_type=target_type, target_id=target_id).first()
    if like:
        if like.value == -1:
            db.session.delete(like)
            val = 0
        else:
            like.value = -1
            val = -1
    else:
        like = Like(user_id=current_user.id, target_type=target_type, target_id=target_id, value=-1)
        db.session.add(like)
        val = -1
    db.session.commit()
    count = db.session.query(func.sum(Like.value)).filter_by(target_type=target_type, target_id=target_id).scalar() or 0
    return jsonify(count=count, val=val)

@app.route('/api/comment', methods=['POST'])
@login_required
def api_comment():
    video_id = int(request.form['video_id'])
    text = request.form['text']
    parent_id = request.form.get('parent_id')
    comment = Comment(video_id=video_id, user_id=current_user.id, text=text, parent_id=parent_id if parent_id else None)
    db.session.add(comment)
    db.session.commit()
    return render_template('_comment.html', comment=comment)

@app.route('/api/subscribe/<int:channel_id>', methods=['POST'])
@login_required
def api_subscribe(channel_id):
    sub = Subscription.query.filter_by(user_id=current_user.id, channel_id=channel_id).first()
    user = User.query.get(channel_id)
    if sub:
        db.session.delete(sub)
        user.subscribers_count -= 1
        subbed = False
    else:
        sub = Subscription(user_id=current_user.id, channel_id=channel_id)
        db.session.add(sub)
        user.subscribers_count += 1
        subbed = True
    db.session.commit()
    return jsonify(subbed=subbed, count=user.subscribers_count)

# Auth
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data) and not user.banned:
            login_user(user)
            return redirect(request.args.get('next') or url_for('index'))
        flash('Invalid credentials or banned.')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash('Email taken.')
            return render_template('register.html', form=form)
        hashed_pw = generate_password_hash(form.password.data)
        user = User(first_name=form.first_name.data, last_name=form.last_name.data, email=form.email.data, password=hashed_pw)
        db.session.add(user)
        db.session.commit()
        flash('Registered! Login.')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/creator/register', methods=['GET', 'POST'])
@login_required
def creator_register():
    if current_user.role != 'user':
        flash('Already creator or pending.')
        return redirect(url_for('index'))
    form = CreatorRegisterForm()
    cloud_name = app.config.get('CLOUDINARY_CLOUD_NAME')
    if form.validate_on_submit():
        current_user.phone = form.phone.data
        current_user.channel_name = form.channel_name.data
        current_user.channel_bio = form.channel_bio.data
        if form.profile_public_id.data:
            current_user.profile_photo = cloudinary.utils.cloudinary_url(form.profile_public_id.data, secure=True)[0]
        current_user.role = 'creator_pending'
        db.session.commit()
        flash('Creator request sent for approval.')
        return redirect(url_for('index'))
    return render_template('creator_register.html', form=form, cloud_name=cloud_name)

@app.route('/bluetick', methods=['GET', 'POST'])
@login_required
def bluetick():
    if current_user.role not in ('creator', 'admin'):
        abort(403)
    ver = Verification.query.filter_by(user_id=current_user.id).first()
    form = BlueTickForm(obj=ver)
    cloud_name = app.config.get('CLOUDINARY_CLOUD_NAME')
    if form.validate_on_submit():
        if not ver:
            ver = Verification(user_id=current_user.id)
            db.session.add(ver)
        ver.instagram = form.instagram.data
        ver.youtube = form.youtube.data
        ver.pan_number = form.pan_number.data
        if form.pan_public_id.data:
            ver.pan_photo = cloudinary.utils.cloudinary_url(form.pan_public_id.data, secure=True)[0]
        ver.reason = form.reason.data
        ver.known_as = form.known_as.data
        ver.category = form.category.data
        ver.status = 'pending'
        ver.rejection_message = None
        db.session.commit()
        flash('Blue tick request submitted.')
        return redirect(url_for('index'))
    return render_template('bluetick.html', form=form, ver=ver, cloud_name=cloud_name)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if current_user.role not in ('creator', 'admin'):
        abort(403)
    form = VideoForm()
    cloud_name = app.config.get('CLOUDINARY_CLOUD_NAME')
    if form.validate_on_submit():
        public_id = form.public_id.data
        video_url = cloudinary.utils.cloudinary_url(public_id + '.m3u8', resource_type='video', secure=True)[0]
        thumbnail_url = cloudinary.utils.cloudinary_url(public_id, resource_type='video', gravity='auto', quality='auto', fetch_format='auto', width=400, crop='thumb', secure=True)[0]
        video = Video(title=form.title.data, description=form.description.data, category=form.category.data,
                      video_url=video_url, thumbnail_url=thumbnail_url, uploader_id=current_user.id,
                      approved=(current_user.role == 'admin'))
        db.session.add(video)
        db.session.commit()
        flash('Video uploaded!' if video.approved else 'Video uploaded, pending approval.')
        return redirect(url_for('index'))
    return render_template('upload.html', form=form, cloud_name=cloud_name)

# Admin
@app.route('/admin/setup', methods=['GET', 'POST'])
def admin_setup():
    if User.query.filter_by(role='admin').count() > 0:
        flash('Admin already exists.')
        return redirect(url_for('login'))
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_pw = generate_password_hash(form.password.data)
        admin = User(first_name=form.first_name.data, last_name=form.last_name.data, email=form.email.data, password=hashed_pw, role='admin')
        db.session.add(admin)
        db.session.commit()
        flash('Admin created! Login.')
        return redirect(url_for('login'))
    return render_template('admin_setup.html', form=form)

@app.route('/admin')
@login_required
def admin():
    if current_user.role != 'admin':
        abort(403)
    views_data = db.session.query(func.date(Video.created_at), func.sum(Video.views)).group_by(func.date(Video.created_at)).all()
    labels = [str(d[0]) for d in views_data]
    data = [d[1] or 0 for d in views_data]
    return render_template('admin.html', labels=labels, data=data)

@app.route('/admin/users')
@login_required
def admin_users():
    if current_user.role != 'admin':
        abort(403)
    users = User.query.filter(User.role != 'admin').order_by(User.created_at.desc()).all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/videos')
@login_required
def admin_videos():
    if current_user.role != 'admin':
        abort(403)
    pending = Video.query.filter_by(approved=False).order_by(Video.created_at.desc()).all()
    return render_template('admin_videos.html', pending=pending)

@app.route('/admin/approve_video/<int:vid_id>')
@login_required
def admin_approve_video(vid_id):
    if current_user.role != 'admin':
        abort(403)
    video = Video.query.get_or_404(vid_id)
    video.approved = True
    db.session.commit()
    flash('Video approved.')
    return redirect(url_for('admin_videos'))

@app.route('/admin/delete_video/<int:vid_id>')
@login_required
def admin_delete_video(vid_id):
    if current_user.role != 'admin':
        abort(403)
    video = Video.query.get_or_404(vid_id)
    db.session.delete(video)
    db.session.commit()
    flash('Video deleted.')
    return redirect(url_for('admin_videos'))

@app.route('/admin/ban_user/<int:user_id>')
@login_required
def admin_ban_user(user_id):
    if current_user.role != 'admin':
        abort(403)
    user = User.query.get_or_404(user_id)
    user.banned = not user.banned
    db.session.commit()
    flash(f'User {"banned" if user.banned else "unbanned"}.')
    return redirect(url_for('admin_users'))

@app.route('/admin/approve_creator/<int:user_id>')
@login_required
def admin_approve_creator(user_id):
    if current_user.role != 'admin':
        abort(403)
    user = User.query.get_or_404(user_id)
    if user.role == 'creator_pending':
        user.role = 'creator'
        db.session.commit()
        flash('Creator approved.')
    return redirect(url_for('admin_users'))

@app.route('/admin/verifications')
@login_required
def admin_verifications():
    if current_user.role != 'admin':
        abort(403)
    vers = Verification.query.filter_by(status='pending').order_by(Verification.created_at.desc()).all()
    return render_template('admin_verifications.html', vers=vers)

@app.route('/admin/approve_ver/<int:ver_id>')
@login_required
def admin_approve_ver(ver_id):
    if current_user.role != 'admin':
        abort(403)
    ver = Verification.query.get_or_404(ver_id)
    ver.status = 'approved'
    ver.user.verified = True
    db.session.commit()
    flash('Blue tick approved.')
    return redirect(url_for('admin_verifications'))

@app.route('/admin/reject_ver/<int:ver_id>', methods=['POST'])
@login_required
def admin_reject_ver(ver_id):
    if current_user.role != 'admin':
        abort(403)
    ver = Verification.query.get_or_404(ver_id)
    ver.status = 'rejected'
    ver.rejection_message = request.form['message']
    db.session.commit()
    flash('Blue tick rejected with message.')
    return redirect(url_for('admin_verifications'))

@app.route('/admin/export/<string:model_name>')
@login_required
def admin_export(model_name):
    if current_user.role != 'admin':
        abort(403)
    if model_name == 'users':
        items = User.query.all()
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['ID', 'Email', 'First Name', 'Last Name', 'Role', 'Banned', 'Verified', 'Subscribers'])
        for item in items:
            writer.writerow([item.id, item.email, item.first_name, item.last_name, item.role, item.banned, item.verified, item.subscribers_count])
        filename = 'users.csv'
    else:
        abort(404)
    return Response(output.getvalue(), mimetype='text/csv', headers={'Content-Disposition': f'attachment; filename={filename}'})

# Run
if __name__ == '__main__':
    app.run(debug=True)
