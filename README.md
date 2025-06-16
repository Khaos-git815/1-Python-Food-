# FlavorNest - Modern Recipe Website

A modern recipe website built with Flask and the Spoonacular API. Search for recipes, view detailed instructions, and discover new dishes.

## Features

- Recipe search functionality
- Detailed recipe pages with ingredients and instructions
- Responsive design
- Modern UI with animations
- Integration with Spoonacular API

## Tech Stack

- **Backend**: Flask, Python
- **Frontend**: HTML, CSS, JavaScript
- **Database**: SQLite (development), PostgreSQL (production)
- **API**: Spoonacular Food API
- **Deployment**: Gunicorn, WhiteNoise

## Local Development

1. Clone the repository:
```bash
git clone <repository-url>
cd flavornest
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Create a `.env` file with your environment variables:
```
SPOONACULAR_API_KEY=your_api_key_here
SECRET_KEY=your_secret_key_here
DATABASE_URL=sqlite:///flavornest.db
```

5. Run the development server:
```bash
python app.py
```

The application will be available at `http://localhost:5000`

## Deployment

### Render

1. Create a new Web Service on Render
2. Connect your GitHub repository
3. Set the following:
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `gunicorn app:app`
4. Add environment variables:
   - `SPOONACULAR_API_KEY`
   - `SECRET_KEY`
   - `DATABASE_URL` (Render will provide this)

### Railway

1. Create a new project on Railway
2. Connect your GitHub repository
3. Add environment variables:
   - `SPOONACULAR_API_KEY`
   - `SECRET_KEY`
   - `DATABASE_URL` (Railway will provide this)
4. Railway will automatically detect the Python app and deploy it

### Fly.io

1. Install the Fly CLI
2. Login to Fly:
```bash
fly auth login
```

3. Launch the app:
```bash
fly launch
```

4. Set secrets:
```bash
fly secrets set SPOONACULAR_API_KEY=your_api_key_here
fly secrets set SECRET_KEY=your_secret_key_here
```

5. Deploy:
```bash
fly deploy
```

## Environment Variables

- `SPOONACULAR_API_KEY`: Your Spoonacular API key
- `SECRET_KEY`: Flask secret key for session security
- `DATABASE_URL`: Database connection URL
- `PORT`: Port number (default: 5000)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details. 
 