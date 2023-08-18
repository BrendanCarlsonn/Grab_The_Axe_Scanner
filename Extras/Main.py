import time

def detect_list_changes(initial_list):
    previous_list = initial_list.copy()

    while True:
        time.sleep(1)  # Adjust the sleep interval as per your requirement

        # Assume you have a function to get the current state of the list, named 'get_current_list()'
        current_list = get_current_list()

        if current_list != previous_list:
            print("List has changed!")
            print("Previous List:", previous_list)
            print("Current List:", current_list)
            previous_list = current_list.copy()

if __name__ == "__main__":
    # Replace 'initial_list' with the initial state of your list
    initial_list = [1, 2, 3, 4, 5]

    detect_list_changes(initial_list)