from gui import passwword_manager_app
from utils import lock_memory

if __name__ == "__main__":
    lock_memory() 
    app = passwword_manager_app()