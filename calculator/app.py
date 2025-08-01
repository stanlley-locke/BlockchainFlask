import math
import statistics
import random
import json
from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

# Calculator implementation
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

    # Game implementations
    def tic_tac_toe(board, player, position):
        if board[position] != ' ':
            return {"status": "error", "message": "Position already taken!"}
        
        board = board.copy()
        board[position] = player
        
        # Check win conditions
        win_conditions = [
            [0, 1, 2], [3, 4, 5], [6, 7, 8],  # rows
            [0, 3, 6], [1, 4, 7], [2, 5, 8],  # columns
            [0, 4, 8], [2, 4, 6]             # diagonals
        ]
        
        winner = None
        for condition in win_conditions:
            if board[condition[0]] == board[condition[1]] == board[condition[2]] != ' ':
                winner = board[condition[0]]
                break
        
        # Check for tie
        if winner is None and ' ' not in board:
            winner = 'T'
        
        next_player = 'O' if player == 'X' else 'X'
        
        return {
            "board": board,
            "next_player": next_player,
            "winner": winner
        }
    
    def guess_number(secret=None, guess=None, attempts=0):
        if secret is None:
            return {"secret": random.randint(1, 100), "attempts": 0}
        
        attempts += 1
        if guess < secret:
            return {"status": "low", "attempts": attempts}
        elif guess > secret:
            return {"status": "high", "attempts": attempts}
        else:
            return {"status": "win", "attempts": attempts}

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
            "guess_number": guess_number
        },
        
        # Conversion units reference
        "conversion_units": conversion_factors
    }

    return calc_dict

# Create calculator instance
calc = calculator()

# API Endpoints
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/calculate', methods=['POST'])
def calculate():
    data = request.json
    operation = data.get('operation')
    params = data.get('params', [])
    
    if operation == 'mean' or operation == 'median' or operation == 'mode' or operation == 'variance' or operation == 'stddev':
        # For statistical functions that take multiple arguments
        result = calc[operation](*params)
    elif operation == 'log':
        if len(params) == 1:
            result = calc[operation](params[0])
        elif len(params) == 2:
            result = calc[operation](params[0], params[1])
        else:
            result = "Error: Invalid number of parameters"
    elif operation == 'round':
        if len(params) == 1:
            result = calc[operation](params[0])
        elif len(params) == 2:
            result = calc[operation](params[0], int(params[1]))
        else:
            result = "Error: Invalid number of parameters"
    elif operation in ['table', 'fibonacci', 'prime']:
        result = calc[operation](params[0])
    elif operation in ['sqrt', 'sin', 'cos', 'tan', 'factorial', 'absolute', 'ceil', 'floor']:
        result = calc[operation](params[0])
    elif operation in ['add', 'subtract', 'multiply', 'divide', 'power', 'modulus', 'gcd', 'lcm']:
        result = calc[operation](params[0], params[1])
    elif operation == 'convert':
        category = data.get('category')
        value = params[0]
        from_unit = data.get('from_unit')
        to_unit = data.get('to_unit')
        result = calc[operation][category](value, from_unit, to_unit)
    else:
        result = "Error: Operation not supported"
    
    return jsonify({"result": result})

@app.route('/api/game', methods=['POST'])
def game():
    data = request.json
    game_type = data.get('game')
    
    if game_type == 'tic_tac_toe':
        board = data.get('board')
        player = data.get('player')
        position = data.get('position')
        result = calc['games']['tic_tac_toe'](board, player, position)
        return jsonify(result)
    
    elif game_type == 'guess_number':
        secret = data.get('secret')
        guess = data.get('guess')
        attempts = data.get('attempts', 0)
        if secret is None:
            result = calc['games']['guess_number']()
        else:
            result = calc['games']['guess_number'](secret, guess, attempts)
        return jsonify(result)
    
    return jsonify({"error": "Game not supported"})

if __name__ == '__main__':
    app.run(debug=True)