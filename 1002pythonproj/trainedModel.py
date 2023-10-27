import pandas as pd
from sklearn.metrics import r2_score, mean_absolute_percentage_error, mean_squared_error, mean_absolute_error
from sklearn.model_selection import train_test_split
import plotly.express as px
from keras.models import Sequential
from keras.layers import Dense
from keras.optimizers import SGD

def get_data():
    df = pd.read_csv('CleanCVEs/cveDetailsFull.csv', usecols=[2,3,4,5,6,7])
    x = df.drop('CVSS_Score', axis=1)
    y = df['CVSS_Score']
    data = pd.get_dummies(x)
    dataset = pd.DataFrame(data)
    dataset = dataset.values
    x = dataset[:, 0:]
    y = y.values
    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2)
    return x_train, x_test, y_train, y_test

def train_model(x_train, x_test, y_train, y_test):
    # define the keras model
    model = Sequential()
    model.add(Dense(100, input_shape=(14,), activation='relu'))
    model.add(Dense(50, activation='relu'))
    model.add(Dense(25, activation='relu'))
    model.add(Dense(1, activation='linear'))
    opt = SGD(lr=0.001)
    model.compile(loss='mean_squared_error', optimizer=opt, metrics=['mse'])
    model.fit(x_train, y_train, epochs=200, batch_size=8, validation_data=(x_test, y_test))
    # evaluate the model
    _, train_mse = model.evaluate(x_train, y_train, verbose=0)
    _, test_mse = model.evaluate(x_test, y_test, verbose=0)
    print('Train: %.3f, Test: %.3f' % (train_mse, test_mse))
    # evaluate the keras model
    _, accuracy = model.evaluate(x_train, y_train)
    print('Accuracy: %.2f' % (accuracy*100))
    ## save model
    save_path = './model.h5'
    model.save(save_path)
    return model

def prediction(model, x_test, y_test):
    predictions = model.predict(x_test)
    print('r2 score is', r2_score(y_test,predictions))
    print('Mean Absolute Percentage Error:', mean_absolute_percentage_error(y_test, predictions))
    print('Mean Absolute Error:', mean_absolute_error(y_test, predictions))
    print('Mean Squared Error:', mean_squared_error(y_test, predictions))
    return predictions

def graph(y_test, predictions):
    pred = [i[0] for i in predictions]
    test = [i for i in y_test]
    difference = y_test-predictions
    pred_df = pd.DataFrame({'Actual CVSS Score': test, 'Predicted CVSS Score': pred})
    fig = px.scatter(
        data_frame=pred_df,
        x='Actual CVSS Score',
        y='Predicted CVSS Score',
        trendline='ols',
        title='Predicted CVSS Score over Actual CVSS Score',
    )
    fig.update_layout(paper_bgcolor='rgba(0,0,0,0)')
    return fig

if __name__ == '__main__':
    # Split data into training and testing data
    x_train, x_test, y_train, y_test = get_data()

    # Train the model
    model = train_model(x_train, x_test, y_train, y_test)

    # Obtain predictions by model based on testing data
    predictions = prediction(model, x_test, y_test)

    # Plot the scatter plot on the predictions
    fig = graph(y_test, predictions)