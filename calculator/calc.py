import math
import statistics
import random
import time
import os
import sys

def calculator():
    def _median(*args):
        if not args:
            return "Error: No numbers provided"
        sorted_args = sorted(args)
        n = len(sorted_args)
        mid = n // 2
        return sorted_args[mid] if n % 2 == 1 else (sorted_args[mid-1] + sorted_args[mid]) / 2

    def _convert_temp(value, from_unit, to_unit):
        to_celsius = {
            'celsius': lambda x: x,
            'fahrenheit': lambda x: (x - 32) * 5/9,
            'kelvin': lambda x: x - 273.15
        }
        from_celsius = {
            'celsius': lambda x: x,
            'fahrenheit': lambda x: (x * 9/5) + 32,
            'kelvin': lambda x: x + 273.15
        }
        try:
            celsius_val = to_celsius[from_unit](value)
            return from_celsius[to_unit](celsius_val)
        except KeyError:
            return "Error: Invalid temperature units"

    def fib(n):
        if n <= 0:
            return []
        if n == 1:
            return [0]
        res = [0, 1]
        for i in range(2, n):
            res.append(res[i-1] + res[i-2])
        return res

    # Conversion factors (base units)
    conversion_factors = {
        'length': {
            'meters': 1,
            'kilometers': 1000,
            'centimeters': 0.01,
            'millimeters': 0.001,
            'inches': 0.0254,
            'feet': 0.3048,
            'yards': 0.9144
        },
        'weight': {
            'grams': 1,
            'kilograms': 1000,
            'milligrams': 0.001,
            'pounds': 453.592,
            'ounces': 28.3495
        },
        'volume': {
            'liters': 1,
            'milliliters': 0.001,
            'gallons': 3.78541,
            'quarts': 0.946353,
            'pints': 0.473176,
            'cups': 0.24
        },
        'speed': {
            'mps': 1,  # meters per second
            'kph': 0.277778,  # kilometers per hour
            'mph': 0.44704,   # miles per hour
            'knots': 0.514444
        },
        'area': {
            'sq_meters': 1,
            'sq_kilometers': 1000000,
            'sq_centimeters': 0.0001,
            'sq_millimeters': 0.000001,
            'sq_inches': 0.00064516,
            'sq_feet': 0.092903,
            'sq_yards': 0.836127
        }
    }

    # Game functions
    def tic_tac_toe():
        board = [' '] * 9
        current_player = 'X'
        game_over = False
        
        def draw_board():
            print(f" {board[0]} | {board[1]} | {board[2]} ")
            print("---|---|---")
            print(f" {board[3]} | {board[4]} | {board[5]} ")
            print("---|---|---")
            print(f" {board[6]} | {board[7]} | {board[8]} ")
        
        def check_winner():
            # Check rows
            for i in range(0, 9, 3):
                if board[i] == board[i+1] == board[i+2] != ' ':
                    return board[i]
            # Check columns
            for i in range(3):
                if board[i] == board[i+3] == board[i+6] != ' ':
                    return board[i]
            # Check diagonals
            if board[0] == board[4] == board[8] != ' ':
                return board[0]
            if board[2] == board[4] == board[6] != ' ':
                return board[2]
            # Check for tie
            if ' ' not in board:
                return 'T'
            return None
        
        while not game_over:
            clear_screen()
            print("=== TIC TAC TOE ===")
            draw_board()
            
            try:
                move = int(input(f"\nPlayer {current_player}, enter position (1-9): ")) - 1
                if move < 0 or move > 8:
                    print("Invalid position! Choose 1-9.")
                    time.sleep(1)
                    continue
                if board[move] != ' ':
                    print("Position already taken!")
                    time.sleep(1)
                    continue
                
                board[move] = current_player
                winner = check_winner()
                
                if winner:
                    clear_screen()
                    draw_board()
                    if winner == 'T':
                        print("\nIt's a tie!")
                    else:
                        print(f"\nPlayer {winner} wins!")
                    game_over = True
                
                # Switch player
                current_player = 'O' if current_player == 'X' else 'X'
            except ValueError:
                print("Please enter a number!")
                time.sleep(1)
        
        input("\nPress Enter to return to menu...")

    def guess_number():
        clear_screen()
        print("=== GUESS THE NUMBER ===")
        print("I'm thinking of a number between 1 and 100!")
        
        number = random.randint(1, 100)
        attempts = 0
        max_attempts = 10
        
        while attempts < max_attempts:
            try:
                guess = int(input(f"\nAttempt {attempts+1}/{max_attempts}: Your guess? "))
                attempts += 1
                
                if guess < number:
                    print("Too low!")
                elif guess > number:
                    print("Too high!")
                else:
                    print(f"\nCorrect! You guessed it in {attempts} attempts!")
                    break
            except ValueError:
                print("Please enter a valid number!")
        
        if attempts >= max_attempts:
            print(f"\nGame over! The number was {number}.")
        
        input("\nPress Enter to return to menu...")

    def flappy_bird():
        clear_screen()
        print("=== FLAPPY BIRD ===")
        print("Press SPACE to flap. Avoid pipes! (Q to quit)")
        input("Press Enter to start...")
        
        # Game constants
        WIDTH = 40
        HEIGHT = 15
        GRAVITY = 0.5
        FLAP_POWER = -3
        PIPE_GAP = 5
        PIPE_FREQ = 20
        
        # Initial state
        bird_y = HEIGHT // 2
        bird_vel = 0
        pipes = []
        score = 0
        game_over = False
        
        def draw_game():
            clear_screen()
            print(f"Score: {score}")
            print("+" + "-" * WIDTH + "+")
            
            for y in range(HEIGHT):
                line = "|"
                for x in range(WIDTH):
                    # Draw bird
                    if x == 5 and y == int(bird_y):
                        line += '@'
                    # Draw pipes
                    elif any(pipe_x <= x < pipe_x + 3 and 
                            (y < pipe_height or y >= pipe_height + PIPE_GAP) 
                            for pipe_x, pipe_height in pipes):
                        line += '#'
                    else:
                        line += ' '
                line += "|"
                print(line)
            
            print("+" + "-" * WIDTH + "+")
            print("Controls: SPACE to flap, Q to quit")
        
        while not game_over:
            # Generate pipes
            if len(pipes) == 0 or pipes[-1][0] < WIDTH - PIPE_FREQ:
                pipe_height = random.randint(2, HEIGHT - PIPE_GAP - 2)
                pipes.append((WIDTH, pipe_height))
            
            # Move pipes
            pipes = [(x - 1, h) for x, h in pipes]
            
            # Remove off-screen pipes
            pipes = [p for p in pipes if p[0] + 3 > 0]
            
            # Apply gravity
            bird_vel += GRAVITY
            bird_y += bird_vel
            
            # Check collisions
            if bird_y < 0 or bird_y >= HEIGHT:
                game_over = True
            
            for pipe_x, pipe_height in pipes:
                if pipe_x <= 5 < pipe_x + 3:
                    if bird_y < pipe_height or bird_y >= pipe_height + PIPE_GAP:
                        game_over = True
            
            # Check for passed pipes
            for pipe_x, pipe_height in pipes:
                if pipe_x + 3 == 5:
                    score += 1
            
            # Draw game state
            draw_game()
            
            # Get input
            try:
                if sys.platform == 'win32':
                    import msvcrt
                    if msvcrt.kbhit():
                        key = msvcrt.getch().decode().lower()
                        if key == ' ':
                            bird_vel = FLAP_POWER
                        elif key == 'q':
                            return
                else:
                    import select
                    if select.select([sys.stdin], [], [], 0) == ([sys.stdin], [], []):
                        key = sys.stdin.read(1).lower()
                        if key == ' ':
                            bird_vel = FLAP_POWER
                        elif key == 'q':
                            return
            except:
                pass
            
            # Slow down game
            time.sleep(0.1)
        
        draw_game()
        print(f"\nGAME OVER! Final score: {score}")
        input("\nPress Enter to return to menu...")

    def hot_air_balloon():
        clear_screen()
        print("=== HOT AIR BALLOON ===")
        print("Press UP to rise, DOWN to descend. Avoid obstacles! (Q to quit)")
        input("Press Enter to start...")
        
        # Game constants
        WIDTH = 60
        HEIGHT = 20
        GRAVITY = 0.2
        LIFT = -0.5
        OBSTACLE_FREQ = 15
        
        # Initial state
        balloon_y = HEIGHT // 2
        balloon_vel = 0
        obstacles = []
        distance = 0
        game_over = False
        
        def draw_game():
            clear_screen()
            print(f"Distance: {distance}")
            print("+" + "-" * WIDTH + "+")
            
            for y in range(HEIGHT):
                line = "|"
                for x in range(WIDTH):
                    # Draw balloon
                    if x == 10 and y == int(balloon_y):
                        line += 'O'
                    # Draw obstacles
                    elif any(obs_x <= x < obs_x + 3 and 
                            (y < obs_gap or y >= obs_gap + 5) 
                            for obs_x, obs_gap in obstacles):
                        line += '#'
                    else:
                        line += ' '
                line += "|"
                print(line)
            
            print("+" + "-" * WIDTH + "+")
            print("Controls: UP/DOWN arrows, Q to quit")
        
        while not game_over:
            # Generate obstacles
            if len(obstacles) == 0 or obstacles[-1][0] < WIDTH - OBSTACLE_FREQ:
                obs_gap = random.randint(3, HEIGHT - 8)
                obstacles.append((WIDTH, obs_gap))
            
            # Move obstacles
            obstacles = [(x - 1, g) for x, g in obstacles]
            
            # Remove off-screen obstacles
            obstacles = [o for o in obstacles if o[0] + 3 > 0]
            
            # Apply gravity
            balloon_vel += GRAVITY
            balloon_y += balloon_vel
            
            # Keep balloon on screen
            if balloon_y < 0:
                balloon_y = 0
                balloon_vel = 0
            if balloon_y >= HEIGHT:
                balloon_y = HEIGHT - 1
                balloon_vel = 0
            
            # Check collisions
            for obs_x, obs_gap in obstacles:
                if obs_x <= 10 < obs_x + 3:
                    if balloon_y < obs_gap or balloon_y >= obs_gap + 5:
                        game_over = True
            
            # Increase distance
            distance += 1
            
            # Draw game state
            draw_game()
            
            # Get input
            try:
                if sys.platform == 'win32':
                    import msvcrt
                    if msvcrt.kbhit():
                        key = msvcrt.getch().decode()
                        if key == chr(72):  # Up arrow
                            balloon_vel = LIFT
                        elif key == chr(80):  # Down arrow
                            balloon_vel = GRAVITY * 2
                        elif key == 'q':
                            return
                else:
                    import select
                    if select.select([sys.stdin], [], [], 0) == ([sys.stdin], [], []):
                        key = sys.stdin.read(1)
                        if key == '\x1b':  # Escape sequence
                            # Read the next two characters
                            if select.select([sys.stdin], [], [], 0) == ([sys.stdin], [], []):
                                key += sys.stdin.read(2)
                                if key == '\x1b[A':  # Up arrow
                                    balloon_vel = LIFT
                                elif key == '\x1b[B':  # Down arrow
                                    balloon_vel = GRAVITY * 2
                        elif key == 'q':
                            return
            except:
                pass
            
            # Slow down game
            time.sleep(0.05)
        
        draw_game()
        print(f"\nGAME OVER! You traveled {distance} units.")
        input("\nPress Enter to return to menu...")

    def mario_jump():
        clear_screen()
        print("=== MARIO JUMP ===")
        print("Press SPACE to jump over Goombas! (Q to quit)")
        input("Press Enter to start...")
        
        # Game constants
        WIDTH = 50
        HEIGHT = 5
        GROUND = HEIGHT - 1
        JUMP_POWER = -3
        GRAVITY = 0.5
        ENEMY_FREQ = 15
        
        # Initial state
        mario_y = GROUND
        mario_vel = 0
        enemies = []
        score = 0
        game_over = False
        is_jumping = False
        
        def draw_game():
            clear_screen()
            print(f"Score: {score}")
            print("+" + "-" * WIDTH + "+")
            
            for y in range(HEIGHT):
                line = "|"
                for x in range(WIDTH):
                    # Draw Mario
                    if x == 5 and y == int(mario_y):
                        line += 'M'
                    # Draw enemies
                    elif any(enemy_x == x and y == GROUND for enemy_x in enemies):
                        line += 'G'  # Goomba
                    # Draw ground
                    elif y == GROUND:
                        line += '_'
                    else:
                        line += ' '
                line += "|"
                print(line)
            
            print("+" + "-" * WIDTH + "+")
            print("Controls: SPACE to jump, Q to quit")
        
        while not game_over:
            # Generate enemies
            if len(enemies) == 0 or enemies[-1] < WIDTH - ENEMY_FREQ:
                enemies.append(WIDTH - 1)
            
            # Move enemies
            enemies = [x - 1 for x in enemies]
            
            # Remove off-screen enemies
            enemies = [e for e in enemies if e > 0]
            
            # Apply gravity
            mario_vel += GRAVITY
            mario_y += mario_vel
            
            # Land on ground
            if mario_y >= GROUND:
                mario_y = GROUND
                mario_vel = 0
                is_jumping = False
            
            # Check collisions
            for enemy_x in enemies:
                if enemy_x == 5 and int(mario_y) == GROUND:
                    game_over = True
            
            # Check for passed enemies
            for enemy_x in enemies:
                if enemy_x == 4:
                    score += 1
            
            # Draw game state
            draw_game()
            
            # Get input
            try:
                if sys.platform == 'win32':
                    import msvcrt
                    if msvcrt.kbhit():
                        key = msvcrt.getch().decode().lower()
                        if key == ' ' and not is_jumping:
                            mario_vel = JUMP_POWER
                            is_jumping = True
                        elif key == 'q':
                            return
                else:
                    import select
                    if select.select([sys.stdin], [], [], 0) == ([sys.stdin], [], []):
                        key = sys.stdin.read(1).lower()
                        if key == ' ' and not is_jumping:
                            mario_vel = JUMP_POWER
                            is_jumping = True
                        elif key == 'q':
                            return
            except:
                pass
            
            # Slow down game
            time.sleep(0.05)
        
        draw_game()
        print(f"\nGAME OVER! Final score: {score}")
        input("\nPress Enter to return to menu...")

    calc_dict = {
        # Basic arithmetic
        "add": lambda x, y: x + y,
        "subtract": lambda x, y: x - y,
        "multiply": lambda x, y: x * y,
        "divide": lambda x, y: x / y if y != 0 else "Error: Division by zero",
        "power": lambda x, y: x ** y,
        "modulus": lambda x, y: x % y if y != 0 else "Error: Modulus by zero",
        
        # Mathematical functions
        "sqrt": lambda x: math.sqrt(x) if x >= 0 else "Error: Negative number",
        "log": lambda x, base=10: math.log(x, base) if x > 0 and base > 0 and base != 1 else "Error: Invalid input",
        "sin": lambda x: math.sin(math.radians(x)),
        "cos": lambda x: math.cos(math.radians(x)),
        "tan": lambda x: math.tan(math.radians(x)),
        "factorial": lambda x: math.factorial(int(x)) if x >= 0 and x == int(x) else "Error: Invalid input",
        "gcd": lambda x, y: math.gcd(int(x), int(y)),
        "lcm": lambda x, y: abs(x * y) // math.gcd(int(x), int(y)) if x and y else 0,
        "absolute": abs,
        "ceil": math.ceil,
        "floor": math.floor,
        "round": round,
        
        # Statistical operations
        "mean": lambda *args: statistics.mean(args) if args else "Error: No numbers provided",
        "median": _median,
        "mode": lambda *args: statistics.mode(args) if args else "Error: No numbers provided",
        "variance": lambda *args: statistics.variance(args) if len(args) > 1 else "Error: Insufficient data",
        "stddev": lambda *args: statistics.stdev(args) if len(args) > 1 else "Error: Insufficient data",
        
        # Constants
        "pi": math.pi,
        "e": math.e,
        
        # Special utilities
        "table": lambda x: [x * i for i in range(1, 11)],
        "fibonacci": lambda n: fib(n) if n >= 0 else "Error: Negative input",
        "prime": lambda n: [x for x in range(2, n+1) if all(x % i != 0 for i in range(2, int(math.sqrt(x)) + 1))] if n >= 2 else [],
        
        # Conversion functions
        "convert": {
            "length": lambda val, frm, to: val * conversion_factors['length'][frm] / conversion_factors['length'][to],
            "weight": lambda val, frm, to: val * conversion_factors['weight'][frm] / conversion_factors['weight'][to],
            "temperature": _convert_temp,
            "volume": lambda val, frm, to: val * conversion_factors['volume'][frm] / conversion_factors['volume'][to],
            "speed": lambda val, frm, to: val * conversion_factors['speed'][frm] / conversion_factors['speed'][to],
            "area": lambda val, frm, to: val * conversion_factors['area'][frm] / conversion_factors['area'][to]
        },
        
        # Games
        "games": {
            "tic_tac_toe": tic_tac_toe,
            "guess_number": guess_number,
            "flappy_bird": flappy_bird,
            "hot_air_balloon": hot_air_balloon,
            "mario_jump": mario_jump
        },
        
        # Conversion units reference
        "conversion_units": conversion_factors
    }

    return calc_dict

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def display_ui(title, options):
    width = 50
    print("\n" + "=" * width)
    print(f"| {title:^46} |")
    print("=" * width)
    for i, option in enumerate(options, 1):
        print(f"| {i:2}. {option:<42} |")
    print("=" * width)
    print("|  0. Exit/Back{'':<30} |")
    print("=" * width)

def execute_operation(calc, op):
    try:
        if op in ["add", "subtract", "multiply", "divide", "power", "modulus", "gcd", "lcm"]:
            a = float(input("Enter first number: "))
            b = float(input("Enter second number: "))
            result = calc[op](a, b)
        elif op in ["sqrt", "sin", "cos", "tan", "factorial", "absolute", "ceil", "floor"]:
            a = float(input("Enter the number: "))
            result = calc[op](a)
        elif op == "log":
            a = float(input("Enter the number: "))
            base_input = input("Enter base (optional, press enter for base 10): ")
            if base_input.strip() == '':
                result = calc[op](a)
            else:
                base = float(base_input)
                result = calc[op](a, base)
        elif op == "round":
            a = float(input("Enter the number: "))
            decimals_input = input("Enter decimals (optional, press enter for 0): ")
            if decimals_input.strip() == '':
                result = calc[op](a)
            else:
                decimals = int(decimals_input)
                result = calc[op](a, decimals)
        elif op in ["mean", "median", "mode", "variance", "stddev"]:
            nums = input("Enter numbers separated by spaces: ").split()
            nums = [float(x) for x in nums]
            result = calc[op](*nums)
        elif op in ["table", "fibonacci", "prime"]:
            n = int(input("Enter the number: "))
            result = calc[op](n)
        else:
            result = calc[op]() if callable(calc[op]) else calc[op]
        
        print(f"\nResult: {result}\n")
        input("Press Enter to continue...")
    except Exception as e:
        print(f"\nError: {str(e)}\n")
        input("Press Enter to continue...")

def conversion_menu(calc):
    while True:
        categories = list(calc["conversion_units"].keys())
        display_ui("UNIT CONVERSION", categories)
        choice = input("Select category: ")
        
        if choice == '0':
            return
        
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(categories):
                category = categories[idx]
                units = list(calc["conversion_units"][category].keys())
                
                display_ui(f"{category.upper()} CONVERSION", units)
                print("=" * 50)
                value = float(input("Enter value: "))
                from_unit = input("Convert from: ").strip()
                to_unit = input("Convert to: ").strip()
                
                if from_unit in units and to_unit in units:
                    result = calc["convert"][category](value, from_unit, to_unit)
                    print(f"\n{value} {from_unit} = {result:.6f} {to_unit}\n")
                else:
                    print("Error: Invalid units selected")
            else:
                print("Invalid selection")
        except ValueError:
            print("Invalid input")
        input("Press Enter to continue...")

def basic_menu(calc):
    ops = ["Addition", "Subtraction", "Multiplication", "Division", 
           "Power", "Modulus", "Absolute", "Round", "Ceil", "Floor"]
    funcs = ["add", "subtract", "multiply", "divide", "power", 
             "modulus", "absolute", "round", "ceil", "floor"]
    
    while True:
        display_ui("BASIC OPERATIONS", ops)
        choice = input("Select operation: ")
        
        if choice == '0':
            return
        
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(funcs):
                execute_operation(calc, funcs[idx])
            else:
                print("Invalid selection")
        except ValueError:
            print("Invalid input")

def scientific_menu(calc):
    ops = ["Square Root", "Logarithm", "Sine", "Cosine", "Tangent", 
           "Factorial", "GCD", "LCM"]
    funcs = ["sqrt", "log", "sin", "cos", "tan", "factorial", "gcd", "lcm"]
    
    while True:
        display_ui("SCIENTIFIC OPERATIONS", ops)
        choice = input("Select operation: ")
        
        if choice == '0':
            return
        
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(funcs):
                execute_operation(calc, funcs[idx])
            else:
                print("Invalid selection")
        except ValueError:
            print("Invalid input")

def stats_menu(calc):
    ops = ["Mean", "Median", "Mode", "Variance", "Standard Deviation"]
    funcs = ["mean", "median", "mode", "variance", "stddev"]
    
    while True:
        display_ui("STATISTICAL OPERATIONS", ops)
        choice = input("Select operation: ")
        
        if choice == '0':
            return
        
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(funcs):
                execute_operation(calc, funcs[idx])
            else:
                print("Invalid selection")
        except ValueError:
            print("Invalid input")

def utilities_menu(calc):
    ops = ["Multiplication Table", "Fibonacci Sequence", "Prime Numbers"]
    funcs = ["table", "fibonacci", "prime"]
    
    while True:
        display_ui("UTILITIES", ops)
        choice = input("Select utility: ")
        
        if choice == '0':
            return
        
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(funcs):
                execute_operation(calc, funcs[idx])
            else:
                print("Invalid selection")
        except ValueError:
            print("Invalid input")

def constants_menu(calc):
    consts = [
        f"Pi: {calc['pi']}",
        f"Euler's Number: {calc['e']}"
    ]
    
    while True:
        display_ui("CONSTANTS", consts)
        choice = input("Select option: ")
        
        if choice == '0':
            return
        
        try:
            if choice == '1':
                print(f"\nPi = {calc['pi']}\n")
            elif choice == '2':
                print(f"\ne = {calc['e']}\n")
            else:
                print("Invalid selection")
            input("Press Enter to continue...")
        except ValueError:
            print("Invalid input")

def games_menu(calc):
    games = [
        "Tic Tac Toe (2 Players)",
        "Guess the Number",
        "Flappy Bird",
        "Hot Air Balloon",
        "Mario Jump"
    ]
    
    game_funcs = [
        calc["games"]["tic_tac_toe"],
        calc["games"]["guess_number"],
        calc["games"]["flappy_bird"],
        calc["games"]["hot_air_balloon"],
        calc["games"]["mario_jump"]
    ]
    
    while True:
        display_ui("GAMES", games)
        choice = input("Select game: ")
        
        if choice == '0':
            return
        
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(game_funcs):
                game_funcs[idx]()
            else:
                print("Invalid selection")
        except ValueError:
            print("Invalid input")

def main():
    calc = calculator()
    
    # ASCII Art Banner
    print(r"""
   _____      _            _       _             
  / ____|    | |          | |     | |            
 | |     __ _| | ___ _   _| | __ _| |_ ___  _ __ 
 | |    / _` | |/ __| | | | |/ _` | __/ _ \| '__|
 | |___| (_| | | (__| |_| | | (_| | || (_) | |   
  \_____\__,_|_|\___|\__,_|_|\__,_|\__\___/|_|   
    """)
    
    main_menu = [
        "Basic Operations",
        "Scientific Functions",
        "Statistical Operations",
        "Unit Conversions",
        "Utilities",
        "Constants",
        "Games"
    ]
    
    while True:
        display_ui("MAIN MENU", main_menu)
        choice = input("Select category: ")
        
        if choice == '0':
            print("\nExiting calculator. Goodbye!\n")
            break
            
        try:
            if choice == '1':
                basic_menu(calc)
            elif choice == '2':
                scientific_menu(calc)
            elif choice == '3':
                stats_menu(calc)
            elif choice == '4':
                conversion_menu(calc)
            elif choice == '5':
                utilities_menu(calc)
            elif choice == '6':
                constants_menu(calc)
            elif choice == '7':
                games_menu(calc)
            else:
                print("Invalid selection")
        except ValueError:
            print("Invalid input")

if __name__ == "__main__":
    main()