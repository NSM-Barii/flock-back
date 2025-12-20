# THIS WILL HOUSE UI CODE



# NSM MODULES
from utilities import Utilities
from flock_finder import Main_Thread


class Main_UI():
    """This module will be responsible for housing UI code"""



    @classmethod
    def main_menu(cls):
        """This will be the main menu before booting in"""

        #Utilities.welcome_ui(iface=iface, text=" FLOCK \nDriving")


        bface, iface, gps, verbose = Utilities.get_args()


        Utilities.clear_screen()
        Utilities.welcome_message(); print('\n\n')
        #iface = Utilities.get_interface(); print('')

        import os, threading

        Main_Thread.main(bface=bface, iface=iface, verbose=verbose)
        #threading.Thread(target=Main_Thread.main, args=(iface, verbose), daemon=True).start()

        print()



if __name__ == "__main__":
    Main_UI.main_menu()




        