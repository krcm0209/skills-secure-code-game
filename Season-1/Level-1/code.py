'''
Welcome to Secure Code Game Season-1/Level-1!

Follow the instructions below to get started:

1. tests.py is passing but code.py is vulnerable
2. Review the code. Can you spot the bug?
3. Fix the code but ensure that tests.py passes
4. Run hack.py and if passing then CONGRATS!
5. If stuck then read the hint
6. Compare your solution with solution.py
'''

from collections import namedtuple
from decimal import Decimal

Order = namedtuple('Order', 'id, items')
Item = namedtuple('Item', 'type, description, amount, quantity')

def validorder(order: Order):
    # Use Decimal for precise financial calculations to avoid floating-point errors
    net = Decimal('0')
    total_payable = Decimal('0')

    # Maximum order limit to prevent integer overflow attacks
    MAX_ORDER_AMOUNT = Decimal('1000000')  # $1M limit

    for item in order.items:
        if item.type == 'payment':
            # Convert to Decimal to ensure precision in financial calculations
            payment_amount = Decimal(str(item.amount))
            net += payment_amount
        elif item.type == 'product':
            # Convert to Decimal and calculate product cost
            product_amount = Decimal(str(item.amount))
            quantity = Decimal(str(item.quantity))
            product_cost = product_amount * quantity

            # Track total payable amount to detect excessive orders
            total_payable += product_cost
            net -= product_cost
        else:
            return "Invalid item type: %s" % item.type

    # Security check: Prevent orders with excessive amounts that could cause overflow
    if total_payable > MAX_ORDER_AMOUNT:
        return "Total amount payable for an order exceeded"

    # Use precise comparison with small tolerance for any remaining precision issues
    # abs(net) < 0.01 means within 1 cent, which is acceptable for financial transactions
    if abs(net) < Decimal('0.01'):
        return "Order ID: %s - Full payment received!" % order.id
    else:
        return "Order ID: %s - Payment imbalance: $%0.2f" % (order.id, float(net))