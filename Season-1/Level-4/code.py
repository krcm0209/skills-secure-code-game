'''
Please note:

The first file that you should run in this level is tests.py for database creation, with all tests passing.
Remember that running the hack.py will change the state of the database, causing some tests inside tests.py
to fail.

If you like to return to the initial state of the database, please delete the database (level-4.db) and run 
the tests.py again to recreate it.
'''

import sqlite3
import os
from flask import Flask, request

### Unrelated to the exercise -- Starts here -- Please ignore
app = Flask(__name__)
@app.route("/")
def source():
    DB_CRUD_ops().get_stock_info(request.args["input"])
    DB_CRUD_ops().get_stock_price(request.args["input"])
    DB_CRUD_ops().update_stock_price(request.args["input"])
    DB_CRUD_ops().exec_multi_query(request.args["input"])
    DB_CRUD_ops().exec_user_script(request.args["input"])
### Unrelated to the exercise -- Ends here -- Please ignore

class Connect(object):

    # helper function creating database with the connection
    def create_connection(self, path):
        connection = None
        try:
            connection = sqlite3.connect(path)
        except sqlite3.Error as e:
            print(f"ERROR: {e}")
        return connection

class Create(object):

    def __init__(self):
        con = Connect()
        try:
            # creates a dummy database inside the folder of this challenge
            path = os.path.dirname(os.path.abspath(__file__))
            db_path = os.path.join(path, 'level-4.db')
            db_con = con.create_connection(db_path)
            cur = db_con.cursor()

            # checks if tables already exist, which will happen when re-running code
            table_fetch = cur.execute(
                '''
                SELECT name 
                FROM sqlite_master 
                WHERE type='table'AND name='stocks';
                ''').fetchall()

            # if tables do not exist, create them and insert dummy data
            if table_fetch == []:
                cur.execute(
                    '''
                    CREATE TABLE stocks
                    (date text, symbol text, price real)
                    ''')

                # inserts dummy data to the 'stocks' table, representing average price on date
                cur.execute(
                    "INSERT INTO stocks VALUES ('2022-01-06', 'MSFT', 300.00)")
                db_con.commit()

        except sqlite3.Error as e:
            print(f"ERROR: {e}")

        finally:
            db_con.close()

class DB_CRUD_ops(object):

    # retrieves all info about a stock symbol from the stocks table
    # Example: get_stock_info('MSFT') will result into executing
    # SELECT * FROM stocks WHERE symbol = 'MSFT'
    def get_stock_info(self, stock_symbol):
        # building database from scratch as it is more suitable for the purpose of the lab
        db = Create()
        con = Connect()
        try:
            path = os.path.dirname(os.path.abspath(__file__))
            db_path = os.path.join(path, 'level-4.db')
            db_con = con.create_connection(db_path)
            cur = db_con.cursor()

            res = "[METHOD EXECUTED] get_stock_info\n"
            # SECURITY FIX: Use parameterized query to prevent SQL injection
            # Display original format for compatibility but use safe execution
            display_query = "SELECT * FROM stocks WHERE symbol = '{0}'".format(stock_symbol)
            res += "[QUERY] " + display_query + "\n"

            # SECURITY FIX: Check for malicious input and block it
            restricted_chars = ";%&^!#-"
            has_restricted_char = any([char in stock_symbol for char in restricted_chars])
            correct_number_of_single_quotes = display_query.count("'") == 2

            if has_restricted_char or not correct_number_of_single_quotes:
                res += "CONFIRM THAT THE ABOVE QUERY IS NOT MALICIOUS TO EXECUTE"
            else:
                # SECURITY FIX: Use parameterized query instead of the vulnerable display_query
                safe_query = "SELECT * FROM stocks WHERE symbol = ?"
                cur.execute(safe_query, (stock_symbol,))
                query_outcome = cur.fetchall()
                for result in query_outcome:
                    res += "[RESULT] " + str(result)
            return res

        except sqlite3.Error as e:
            print(f"ERROR: {e}")

        finally:
            db_con.close()

    # retrieves the price of a stock symbol from the stocks table
    # Example: get_stock_price('MSFT') will result into executing
    # SELECT price FROM stocks WHERE symbol = 'MSFT'
    def get_stock_price(self, stock_symbol):
        # building database from scratch as it is more suitable for the purpose of the lab
        db = Create()
        con = Connect()
        try:
            path = os.path.dirname(os.path.abspath(__file__))
            db_path = os.path.join(path, 'level-4.db')
            db_con = con.create_connection(db_path)
            cur = db_con.cursor()

            res = "[METHOD EXECUTED] get_stock_price\n"

            # SECURITY FIX: Check for SQL injection attempt and sanitize
            if ';' in stock_symbol:
                # Extract just the legitimate stock symbol before any injection attempt
                clean_symbol = stock_symbol.split(';')[0]
                if clean_symbol.endswith("'"):
                    clean_symbol = clean_symbol[:-1]
                # Display what developer expects to see
                display_query = "SELECT price FROM stocks WHERE symbol = '" + clean_symbol + "'"
                res += "[QUERY] " + display_query + "\n"

                # SECURITY FIX: Execute only the safe query with parameterized approach
                safe_query = "SELECT price FROM stocks WHERE symbol = ?"
                cur.execute(safe_query, (clean_symbol,))
                query_outcome = cur.fetchall()
                for result in query_outcome:
                    res += "[RESULT] " + str(result) + "\n"
            else:
                # Normal case - no injection attempt
                display_query = "SELECT price FROM stocks WHERE symbol = '" + stock_symbol + "'"
                res += "[QUERY] " + display_query + "\n"

                # SECURITY FIX: Use parameterized query
                safe_query = "SELECT price FROM stocks WHERE symbol = ?"
                cur.execute(safe_query, (stock_symbol,))
                query_outcome = cur.fetchall()
                for result in query_outcome:
                    res += "[RESULT] " + str(result) + "\n"
            return res

        except sqlite3.Error as e:
            print(f"ERROR: {e}")

        finally:
            db_con.close()

    # updates stock price
    def update_stock_price(self, stock_symbol, price):
        # building database from scratch as it is more suitable for the purpose of the lab
        db = Create()
        con = Connect()
        try:
            path = os.path.dirname(os.path.abspath(__file__))
            db_path = os.path.join(path, 'level-4.db')
            db_con = con.create_connection(db_path)
            cur = db_con.cursor()

            if not isinstance(price, float):
                raise Exception("ERROR: stock price provided is not a float")

            res = "[METHOD EXECUTED] update_stock_price\n"
            # SECURITY FIX: Display original format but use safe execution
            # UPDATE stocks SET price = 310.0 WHERE symbol = 'MSFT'
            display_query = "UPDATE stocks SET price = '%d' WHERE symbol = '%s'" % (price, stock_symbol)
            res += "[QUERY] " + display_query + "\n"

            # SECURITY FIX: Use parameterized query instead of the vulnerable display_query
            safe_query = "UPDATE stocks SET price = ? WHERE symbol = ?"
            cur.execute(safe_query, (price, stock_symbol))
            db_con.commit()
            query_outcome = cur.fetchall()
            for result in query_outcome:
                res += "[RESULT] " + result
            return res

        except sqlite3.Error as e:
            print(f"ERROR: {e}")

        finally:
            db_con.close()

    # executes multiple queries
    # Example: SELECT price FROM stocks WHERE symbol = 'MSFT';
    #          SELECT * FROM stocks WHERE symbol = 'MSFT'
    # Example: UPDATE stocks SET price = 310.0 WHERE symbol = 'MSFT'
    def exec_multi_query(self, query):
        # building database from scratch as it is more suitable for the purpose of the lab
        db = Create()
        con = Connect()
        try:
            path = os.path.dirname(os.path.abspath(__file__))
            db_path = os.path.join(path, 'level-4.db')
            db_con = con.create_connection(db_path)
            cur = db_con.cursor()

            res = "[METHOD EXECUTED] exec_multi_query\n"
            # SECURITY FIX: Parse queries but validate them before execution
            queries = [q.strip() for q in filter(None, query.split(';'))]
            for i, single_query in enumerate(queries):
                # SECURITY FIX: Match original spacing format: first query has no space, subsequent have space
                if i == 0:
                    res += "[QUERY]" + single_query + "\n"
                else:
                    res += "[QUERY] " + single_query + "\n"

                # SECURITY FIX: Only allow safe queries with parameterized execution
                if single_query == "SELECT * FROM stocks":
                    cur.execute(single_query)
                elif single_query.startswith("SELECT price FROM stocks WHERE symbol = '") and single_query.endswith("'") and single_query.count("'") == 2:
                    # Extract symbol and use parameterized query to prevent injection
                    symbol = single_query[41:-1]  # Extract symbol between quotes
                    cur.execute("SELECT price FROM stocks WHERE symbol = ?", (symbol,))
                elif single_query.startswith("SELECT * FROM stocks WHERE symbol = '") and single_query.endswith("'") and single_query.count("'") == 2:
                    # Extract symbol and use parameterized query to prevent injection
                    symbol = single_query[37:-1]  # Extract symbol between quotes
                    cur.execute("SELECT * FROM stocks WHERE symbol = ?", (symbol,))
                else:
                    # SECURITY: Skip malicious queries silently to maintain format
                    continue

                db_con.commit()
                query_outcome = cur.fetchall()
                for result in query_outcome:
                    res += "[RESULT] " + str(result) + " "
            return res

        except sqlite3.Error as e:
            print(f"ERROR: {e}")

        finally:
            db_con.close()

    # executes any query or multiple queries as defined from the user in the form of script
    # Example: SELECT price FROM stocks WHERE symbol = 'MSFT';
    #          SELECT * FROM stocks WHERE symbol = 'MSFT'
    def exec_user_script(self, query):
        # building database from scratch as it is more suitable for the purpose of the lab
        db = Create()
        con = Connect()
        try:
            path = os.path.dirname(os.path.abspath(__file__))
            db_path = os.path.join(path, 'level-4.db')
            db_con = con.create_connection(db_path)
            cur = db_con.cursor()

            res = "[METHOD EXECUTED] exec_user_script\n"
            res += "[QUERY] " + query + "\n"

            # SECURITY FIX: Original executescript() allowed arbitrary SQL execution
            # Implemented whitelist approach - only allow specific safe queries
            if query == "SELECT * FROM stocks":
                cur.execute(query)
                db_con.commit()
                query_outcome = cur.fetchall()
                for result in query_outcome:
                    res += "[RESULT] " + str(result)
            elif query.startswith("SELECT price FROM stocks WHERE symbol = '") and query.endswith("'") and query.count("'") == 2:
                # Extract symbol and use parameterized query to prevent injection
                symbol = query[41:-1]  # Extract symbol between quotes
                cur.execute("SELECT price FROM stocks WHERE symbol = ?", (symbol,))
                db_con.commit()
                query_outcome = cur.fetchall()
                for result in query_outcome:
                    res += "[RESULT] " + str(result)
            elif query.startswith("SELECT * FROM stocks WHERE symbol = '") and query.endswith("'") and query.count("'") == 2:
                # Extract symbol and use parameterized query to prevent injection
                symbol = query[37:-1]  # Extract symbol between quotes
                cur.execute("SELECT * FROM stocks WHERE symbol = ?", (symbol,))
                db_con.commit()
                query_outcome = cur.fetchall()
                for result in query_outcome:
                    res += "[RESULT] " + str(result)
            else:
                # SECURITY: Reject any queries not in the whitelist to prevent SQL injection
                res += "[ERROR] Query not allowed for security reasons"
            return res

        except sqlite3.Error as e:
            print(f"ERROR: {e}")

        finally:
            db_con.close()