*This is only conception - don't hesitate to make changes and improvements.*

The main target - create easy to use and flexible library for creating and sending emails. Big emphasis on flexibility.

Under the hood we should use django infrastructure.

## First implementation

Implement abstract class for next two classes

Implement base-class that handle rendering for simple text emails. Requirements:
- template-based rendering of messages

Implement base-class that handle rendering for html-emails *(may inherit from previous?)*. Requirements:
- template-based rendering of messages and html
- separate rendering of html-template and message-template

Implement class handler of sending emails. Requirements:
- must handle sending emails
- supporting of custom args and kwargs
- *(should have two types of sending strategy - sync and async(using celery))?* - can be moved to **Second implementation** but should be in mind at the time of realization.

Implement class-registry that register email classes. Implement our own (http://code.saghul.net/index.php/2011/01/09/implementing-registry-pattern-with-class-decorators/) or use existing library (https://pypi.org/project/class-registry/).
Requirements:
- must support decorator pattern

Posible usecases:

```
import SimpleEmailRegister

@SimpleEmailRegister.register_text('reset-password')
@SimpleEmailRegister.register_html('reset-password')
class ResetPasswordEmail(HTMLEmail):
    subject = 'Reset Password'
    html_template = 'my_app/my_html_template.html'
    message_template = 'my_app/my_plain_text_template.html'
    
    # overriding message rendering context
    def get_message_context(self):
        context = super().get_message_context()
        context['my-custom-variable'] = 'White Wolf'
        return context

# serializers.py - usage 
import SimpleEmailHandler

class ResetPasswordSerializer(serializers.Serializer):
    def create(self, validated_data):
        # ...
        SimpleEmailHandler.handle('reset-password', user_id, **some_additional_info) # accept any number of args and kwargs
```

## Second implementation

Additional features:
- sync and async email-sending strategies
- calendar attachment
- map-location attachment
- autodiscovering of email classes
