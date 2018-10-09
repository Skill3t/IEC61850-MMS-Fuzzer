from anytree import NodeMixin, RenderTree
class MyBaseClass(object):
    foo = 4

class Tree(MyBaseClass, NodeMixin):  # Add Node feature
    '''
    ASN1 Tree object. ASN1 is a struct in the form of: data, lenght, payload
    the payload can be one ore multiple objects with data, lenght, payload
    '''
    def __init__(self, name, mmstype, blength,ilength , payload, parent=None):
        super(Tree, self).__init__()
        self.name = name
        self.mmstype = mmstype
        self.blength = blength
        self.ilength = ilength
        self.payload = payload
        self.parent = parent
