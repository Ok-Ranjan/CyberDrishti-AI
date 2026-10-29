import re
from urllib.parse import urlparse

def analyze_message(message):

    text = message.strip()
    normalized_text = text.lower()

    indicators = []
    score=0

    def add_indicator(points, category, explanation):
        nonlocal score

        score += points
        indicators.append({
            "category": category,
            "points": points,
            "explanation": explanation
        })