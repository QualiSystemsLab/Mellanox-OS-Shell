python -m unittest discover -s tests/

pip install coverage

del /s /q htmlcov

coverage run --branch -m unittest discover -s tests/

coverage report -m

coverage html
start htmlcov/index.html
