from entities.controller import Controller

from certification.config import CERTS_DIR

import os
import shutil


def create_certificates_folder():
    """
    Creates the Certificate entities' folder
    :return:
    """
    if os.path.exists(CERTS_DIR):
        shutil.rmtree(CERTS_DIR)
    os.makedirs(CERTS_DIR)


def print_instructions():
    """
    Prints the manual for using the program
    :return:
    """
    print("Welcome to Public Key Infrastructure project!")
    print("These are the main commands:")
    print("\tgenerate - Generate an Entity")
    print("\tsend - Send a message")
    print("\tshow - Show entities")
    print('\trevoke - Revoke an entity of your choice')
    print("\thelp - Print this instructions again")
    print("\tquit - Quit the program")


cmds = {"generate": Controller.generate, "send": Controller.send_message,
        "revoke": Controller.revoke, "show": Controller.show_entities,
        "help": print_instructions, "quit": Controller.shut_entities}

if __name__ == '__main__':
    create_certificates_folder()
    print_instructions()
    print("Note: Enter an entity by entering it's ID which is the number it is given. "
          "For example, Entity1 has an ID 1, so enter 1 for relevant commands.")
    print("Very well!")
    while True:
        cmd = input("Enter command: ")
        if cmd in cmds:
            try:
                cmds[cmd]()
                if cmd == 'quit':
                    break
            except Exception as e:
                print(e)
        else:
            print("Unknown command. Please enter a correct command. If you having trouble, "
                  "you can enter the command 'help' to see again what are the valid commands.")
