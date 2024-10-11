class ContainerType(object):
    Model = 'Model'
    Serializer = 'Serializer'
    Entity = 'Entity'
    Data = 'Data'

    # A serializer is not input by deffault, a database is.
    used_for_input = (Model, Entity, Data)


class HttpMethods(object):
    Post = 'post'
    Get = 'get'
    Put = 'put'
    Patch = 'patch'
    Delete = 'delete'

    all = (Post, Put, Patch, Get, Delete)
    input = (Post, Put, Patch)
