#!/usr/bin/env python3
import math
import statistics
import random
import time
import sys

# ANSI color codes for styling
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# ---------------------------------------------
# Core Calculator Functions and Conversions
# ---------------------------------------------

def median_custom(*args):
    sorted_args = sorted(args)
    n = len(sorted_args)
    if n == 0:
        raise ValueError("No data")
    mid = n // 2
    return sorted_args[mid] if n % 2 else (sorted_args[mid-1] + sorted_args[mid]) / 2

conversion_factors = {
    'length':    {'meters':1,'kilometers':1000,'centimeters':0.01,'millimeters':0.001,'inches':0.0254,'feet':0.3048,'yards':0.9144},
    'weight':    {'grams':1,'kilograms':1000,'milligrams':0.001,'pounds':453.592,'ounces':28.3495},
    'volume':    {'liters':1,'milliliters':0.001,'gallons':3.78541,'quarts':0.946353,'pints':0.473176,'cups':0.24},
    'speed':     {'mps':1,'kph':0.277778,'mph':0.44704,'knots':0.514444},
    'area':      {'sq_meters':1,'sq_kilometers':1e6,'sq_centimeters':1e-4,'sq_millimeters':1e-6,'sq_inches':0.00064516,'sq_feet':0.092903,'sq_yards':0.836127}
}

def convert_temperature(value, frm, to):
    to_c = {'celsius':lambda x:x,'fahrenheit':lambda x:(x-32)*5/9,'kelvin':lambda x:x-273.15}
    from_c = {'celsius':lambda x:x,'fahrenheit':lambda x:x*9/5+32,'kelvin':lambda x:x+273.15}
    if frm not in to_c or to not in from_c:
        raise ValueError("Invalid temperature units")
    c = to_c[frm](value)
    return from_c[to](c)

# Generator for primes
def prime_generator(count):
    yielded = 0
    num = 2
    primes = []
    while yielded < count:
        if all(num % p for p in primes if p*p <= num):
            primes.append(num)
            yield num
            yielded += 1
        num += 1

# Fibonacci sequence
def fibonacci(n):
    if n < 1:
        return []
    seq = [0,1]
    while len(seq) < n:
        seq.append(seq[-1] + seq[-2])
    return seq[:n]

# Calculator operations mapping
def make_calc_dict():
    return {
        'add': lambda x,y: x+y,
        'subtract': lambda x,y: x-y,
        'multiply': lambda x,y: x*y,
        'divide': lambda x,y: x/y if y!=0 else float('nan'),
        'power': lambda x,y: x**y,
        'modulus': lambda x,y: x%y if y!=0 else float('nan'),
        'sqrt': lambda x: math.sqrt(x),
        'log': lambda x,base=10: math.log(x,base),
        'sin': lambda x: math.sin(math.radians(x)),
        'cos': lambda x: math.cos(math.radians(x)),
        'tan': lambda x: math.tan(math.radians(x)),
        'factorial': lambda x: math.factorial(int(x)),
        'gcd': lambda x,y: math.gcd(int(x),int(y)),
        'lcm': lambda x,y: abs(int(x)*int(y))//math.gcd(int(x),int(y)),
        'absolute': abs,
        'ceil': math.ceil,
        'floor': math.floor,
        'round': round,
        'mean': lambda *args: statistics.mean(args),
        'median': lambda *args: median_custom(*args),
        'mode': lambda *args: statistics.mode(args),
        'variance': lambda *args: statistics.variance(args),
        'stddev': lambda *args: statistics.stdev(args),
        'pi': math.pi,
        'e': math.e,
        'table': lambda x: [x*i for i in range(1,11)],
        'fibonacci': lambda n: fibonacci(int(n)),
        'prime_list': lambda n: [p for p in range(2,int(n)+1) if all(p%i for i in range(2,int(math.sqrt(p))+1))],
        'prime_gen': lambda c: prime_generator(int(c)),
        'convert_temp': lambda v,frm,to: convert_temperature(v,frm,to),
        'convert': conversion_factors
    }

# ---------------------------------------------
# ASCII Games Implementations
# ---------------------------------------------

def play_guess_number():
    print(Colors.OKBLUE + "\n-- Guess the Number --" + Colors.ENDC)
    n = random.randint(1,100)
    attempts = 0
    while True:
        try:
            guess = int(input("Enter guess (1-100): "))
            attempts += 1
            if guess < n:
                print(Colors.WARNING + "Too low" + Colors.ENDC)
            elif guess > n:
                print(Colors.WARNING + "Too high" + Colors.ENDC)
            else:
                print(Colors.OKGREEN + f"Correct! Attempts: {attempts}" + Colors.ENDC)
                break
        except ValueError:
            print(Colors.FAIL + "Invalid input" + Colors.ENDC)


def play_tic_tac_toe():
    print(Colors.OKBLUE + "\n-- Tic-Tac-Toe --" + Colors.ENDC)
    board = [' '] * 9
    wins = [(0,1,2),(3,4,5),(6,7,8),(0,3,6),(1,4,7),(2,5,8),(0,4,8),(2,4,6)]
    player = 'X'
    def display():
        print('\n'.join([f" {board[i]} | {board[i+1]} | {board[i+2]}" for i in (0,3,6)]))
    for turn in range(9):
        display()
        while True:
            move = input(f"Player {player}, choose 1-9: ")
            if move.isdigit() and 1 <= (m:=int(move)) <= 9 and board[m-1]==' ':
                board[m-1] = player
                break
            print(Colors.FAIL + "Invalid move" + Colors.ENDC)
        if any(board[a]==board[b]==board[c]==player for a,b,c in wins):
            display()
            print(Colors.OKGREEN + f"Player {player} wins!" + Colors.ENDC)
            return
        player = 'O' if player=='X' else 'X'
    display()
    print(Colors.WARNING + "Draw!" + Colors.ENDC)


def play_mario_runner():
    print(Colors.OKBLUE + "\n-- Mario Runner --" + Colors.ENDC)
    length = 40
    pos = 0
    obstacles = random.sample(range(10, length), 8)
    for step in range(length):
        line = ['_']*length
        for o in obstacles:
            if 0 <= o-step < length:
                line[o-step] = '#'
        if pos==0:
            line[0] = 'M'
        print(''.join(line))
        cmd = input("Press Enter to move, 'j'+Enter to jump: ")
        if cmd.lower()=='j' and step in obstacles:
            print(Colors.OKGREEN + "Jumped!" + Colors.ENDC)
        elif step in obstacles:
            print(Colors.FAIL + "Hit obstacle! Game Over." + Colors.ENDC)
            return
    print(Colors.OKGREEN + "Mario crossed the course!" + Colors.ENDC)


def play_flappy_bird():
    print(Colors.OKBLUE + "\n-- Flappy Bird --" + Colors.ENDC)
    height, width = 10, 30
    bird_y = height//2
    pipes = []
    tick = 0
    while True:
        tick += 1
        if tick % 12 == 0:
            gap = random.randint(2, height-3)
            pipes.append({'x': width-1, 'gap': gap})
        screen = [[' ']*width for _ in range(height)]
        for pipe in pipes:
            x = pipe['x']
            for y in range(height):
                if not(pipe['gap'] <= y < pipe['gap']+3) and 0<=x<width:
                    screen[y][x] = '|'
            pipe['x'] -= 1
        if screen[bird_y][5] == '|':
            print(Colors.FAIL + "Collision! Game Over." + Colors.ENDC)
            break
        screen[bird_y][5] = 'B'
        print('\n'.join(''.join(row) for row in screen))
        cmd = input("Enter to flap, any to fall: ")
        bird_y = max(0, bird_y-1) if cmd=='' else min(height-1, bird_y+1)
        time.sleep(0.1)
        print("\033c", end='')
    print(Colors.OKWHITE if hasattr(Colors,'OKWHITE') else '', end='')


def play_hot_air_balloon():
    print(Colors.OKBLUE + "\n-- Hot Air Balloon --" + Colors.ENDC)
    height, width = 10, 20
    x, y = width//2, height//2
    while True:
        for i in range(height):
            line = [' ']*width
            if i==y: line[x] = 'O'
            print(''.join(line))
        cmd = input("Type 'heat'/'cool'/'exit': ")
        if cmd=='heat': y = max(0, y-1)
        elif cmd=='cool': y = min(height-1, y+1)
        elif cmd=='exit': print(Colors.OKGREEN + "Balloon landed." + Colors.ENDC); break
        else: print(Colors.FAIL + "Unknown command" + Colors.ENDC)
        print("\033c", end='')

# ---------------------------------------------
# ASCII CLI Menus and Main Loop
# ---------------------------------------------

def display_menu(title, options):
    print(Colors.HEADER + '\n' + '='*40 + f"\n  {title:^36}\n" + '='*40 + Colors.ENDC)
    for i,opt in enumerate(options,1):
        print(Colors.OKGREEN + f" {i}. {opt}" + Colors.ENDC)
    print(Colors.WARNING + " 0. Exit" + Colors.ENDC)


def main():
    calc = make_calc_dict()
    main_options = [
        'Basic Arithmetic',
        'Scientific Functions',
        'Statistics',
        'Conversions',
        'Utilities',
        'Games'
    ]
    while True:
        display_menu('MAIN MENU', main_options)
        choice = input('Select: ')
        if choice=='0': break
        if choice=='1':
            ops = ['add','subtract','multiply','divide','power','modulus']
        elif choice=='2':
            ops = ['sqrt','log','sin','cos','tan','factorial','gcd','lcm']
        elif choice=='3':
            ops = ['mean','median','mode','variance','stddev']
        elif choice=='4':
            ops = ['convert_temp'] + list(conversion_factors.keys())
        elif choice=='5':
            ops = ['table','fibonacci','prime_list','prime_gen']
        elif choice=='6':
            game_ops = ['Guess Number','Tic-Tac-Toe','Mario Runner','Flappy Bird','Hot Air Balloon']
            display_menu('GAMES', game_ops)
            g = input('Select game: ')
            if g=='1': play_guess_number()
            elif g=='2': play_tic_tac_toe()
            elif g=='3': play_mario_runner()
            elif g=='4': play_flappy_bird()
            elif g=='5': play_hot_air_balloon()
            continue
        else:
            print(Colors.FAIL + "Invalid selection" + Colors.ENDC)
            continue
        display_menu('OPTIONS', ops)
        sel = input('Select: ')
        if not sel.isdigit() or int(sel)<1 or int(sel)>len(ops):
            print(Colors.FAIL + "Invalid" + Colors.ENDC)
            continue
        op = ops[int(sel)-1]
        # handle conversions specially
        if op=='convert_temp':
            v=float(input('Value: '))
            frm=input('From unit: ')
            to=input('To unit: ')
            res = calc['convert_temp'](v,frm,to)
        elif op in conversion_factors:
            v=float(input('Value: '))
            frm=input('From unit: ')
            to=input('To unit: ')
            res = v*conversion_factors[op][frm]/conversion_factors[op][to]
        elif op=='prime_gen':
            c=int(input('Count: '))
            for p in calc['prime_gen'](c): print(p)
            input('Enter to continue')
            continue
        else:
            # numeric args
            func = calc[op]
            params = func.__code__.co_argcount
            args = []
            for _ in range(params): args.append(float(input('Enter number: ')))
            res = func(*args)
        print(Colors.OKCYAN + f"Result: {res}" + Colors.ENDC)
        input('Enter to continue')
    print(Colors.OKBLUE + '\nGoodbye!' + Colors.ENDC)

if __name__=='__main__':
    main()
