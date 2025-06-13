#nc 20.255.51.113 1212
import random
from secret import FLAG

def win_flag():
    print(FLAG)
def print_puzzle(puzzle):
    for row in puzzle:
        print(" ".join([str(x) if x != 0 else "_" for x in row]))
    print()

def is_solved(puzzle):
    goal = [1, 2, 3, 4, 5, 6, 7, 8, 0]
    flat_puzzle = sum(puzzle, [])
    return flat_puzzle == goal

def find_empty(puzzle):
    for i in range(3):
        for j in range(3):
            if puzzle[i][j] == 0:
                return i, j

def swap(puzzle, pos1, pos2):
    puzzle[pos1[0]][pos1[1]], puzzle[pos2[0]][pos2[1]] = puzzle[pos2[0]][pos2[1]], puzzle[pos1[0]][pos1[1]]

def create_puzzle():
    puzzle = [1, 2, 3, 4, 5, 6, 7, 8, 0]
    random.shuffle(puzzle)
    return [puzzle[:3], puzzle[3:6], puzzle[6:]]

def move(puzzle, direction):
    i, j = find_empty(puzzle)
    if direction == "s" and i < 2:       
        swap(puzzle, (i, j), (i + 1, j))
    elif direction == "w" and i > 0:  
        swap(puzzle, (i, j), (i - 1, j))
    elif direction == "d" and j < 2:   
        swap(puzzle, (i, j), (i, j + 1))
    elif direction == "a" and j > 0:  
        swap(puzzle, (i, j), (i, j - 1))
    else:
        print("Move not possible!")


print("Welcome to the 8-Puzzle Game!")
print("Your goal is to arrange the numbers from 1 to 8 with the blank space (_) in the last position.")
print("""1 2 3\n4 5 6\n7 8 _""")
print("You can move the blank space by entering 'up', 'down', 'left', or 'right'.")
print("Let's start the game!\n")
puzzle = create_puzzle()
while not is_solved(puzzle):
    print_puzzle(puzzle)
    move_direction = input("Enter move (w = up , s = down, a = left, d = right): ").strip().lower()
    move(puzzle, move_direction)

print("Congratulations! You solved the puzzle!")
win_flag()



