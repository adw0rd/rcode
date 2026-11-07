import re


def slugify(text):
    text = text.lower()
    text = re.sub(r'[\s-]+', '-', text)
    return text.strip('-')


def title_slug(text):
    return slugify(text)
