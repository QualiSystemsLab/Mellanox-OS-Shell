pip install coverage

del /s /q htmlcov

coverage run -m unittest discover -s tests/

coverage report -m

coverage html
start htmlcov/index.html
