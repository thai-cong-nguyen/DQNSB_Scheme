class View: 
    def __init__(self, view_number, num_nodes) -> None:
        self._view_number = view_number
        self._num_nodes = num_nodes
        self._leader

    # to encode to json
    def get(self):
        return self._view_number
    # recover from json data
    def set_view(self, view):
        self._view_number = view
        self._
    

class Status:
    def __init__(self) -> None:
        pass

class Client:
    REQUEST = 'request'
    REPLY = 'reply'
    VIEW_CHANGE_REQUEST = 'view_change_request'

# def setup(args = None):

def run_app(client):
    address = client._address
    host = address['host']
    port = address['port']

    
    


