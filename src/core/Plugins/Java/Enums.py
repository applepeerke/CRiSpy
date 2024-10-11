class AccessModifier(object):
    Private = 'private'
    Protected = 'protected'
    Public = 'public'
    PackagePrivate = 'package-private'

    items = (Private, Protected, Public, PackagePrivate)


class NonAccessModifier(object):
    final = 'final'
    static = 'static'
    abstract = 'abstract'
    transient = 'transient'
    volatile = 'volatile'
    synchronized = 'synchronized'

    items = (final, static, abstract, transient, volatile, synchronized)
